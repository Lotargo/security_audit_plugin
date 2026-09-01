/**
 * Hardened Playwright browser runner for DAST audits.
 * Config is accepted either as legacy argv JSON/URL or, preferably, via --stdin-json so
 * authentication headers and cookies do not appear in the process list.
 */

import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { setupHumanCursor, humanDelay, humanScroll } from './mouse_bezier.js';
import { WafDetector } from './waf_detector.js';
import { runDecoyBurst } from './decoy_traffic.js';
import fs from 'fs/promises';
import path from 'path';
import dns from 'dns/promises';

chromium.use(stealthPlugin());

function normalizeHost(host) {
  const value = String(host || '').trim().toLowerCase();
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

function normalizeAllowedHosts(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeHost).filter(Boolean))].sort();
}

function isPrivateOrRestrictedIp(ipStr) {
  if (!ipStr) return true;
  const ip = normalizeHost(ipStr);

  if (ip.startsWith('127.') || ip === '0.0.0.0') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('169.254.')) return true;
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(ip)) return true;
  if (
    ip === '::1' ||
    ip === '::' ||
    ip.startsWith('fe80:') ||
    ip.startsWith('fc00:') ||
    ip.startsWith('fd00:')
  )
    return true;
  if (ip.startsWith('::ffff:') || ip.startsWith('64:ff9b:')) {
    const v4part = ip.split(':').pop();
    if (v4part && isPrivateOrRestrictedIp(v4part)) return true;
  }
  return false;
}

async function classifyUrl(urlStr, allowPrivate = false, allowedHosts = [], resolveDns = true) {
  try {
    const parsed = new URL(urlStr);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, reason: `Unsupported protocol: ${parsed.protocol}` };
    }

    const host = normalizeHost(parsed.hostname);
    if (allowedHosts.length > 0 && !allowedHosts.includes(host)) {
      return { ok: false, reason: `Host is outside active RoE scope: ${host}` };
    }

    if (allowPrivate) return { ok: true, reason: 'allow_private' };

    const literalIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':');
    if (literalIp && isPrivateOrRestrictedIp(host)) {
      return { ok: false, reason: `Direct private IP access blocked: ${host}` };
    }

    // With a scoped SOCKS proxy the destination hostname must be resolved by the proxy itself.
    // Local dns.lookup() here would leak the target and would also make .onion destinations fail.
    if (!resolveDns) {
      return { ok: true, reason: 'scoped_proxy_dns' };
    }

    try {
      const records = await dns.lookup(host, { all: true });
      for (const record of records) {
        if (isPrivateOrRestrictedIp(record.address)) {
          return { ok: false, reason: `DNS resolves to restricted private IP: ${host} -> ${record.address}` };
        }
      }
    } catch (dnsErr) {
      return { ok: false, reason: `DNS resolution failed for ${host}: ${dnsErr.message}` };
    }

    return { ok: true, reason: 'public' };
  } catch (err) {
    return { ok: false, reason: `URL parse error: ${err.message}` };
  }
}

async function readConfig() {
  const args = process.argv.slice(2);
  if (args[0] === '--stdin-json') {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString('utf-8');
    if (!raw.trim()) throw new Error('Empty browser config on stdin');
    return JSON.parse(raw);
  }

  if (args[0]) {
    try {
      return JSON.parse(args[0]);
    } catch {
      return { url: args[0] };
    }
  }
  throw new Error('Browser audit requires an explicit target URL');
}

async function runAudit() {
  const config = await readConfig();
  const targetUrl = config.url;
  if (!targetUrl) throw new Error('Browser audit config is missing url');

  const allowedHosts = normalizeAllowedHosts(config.allowed_hosts);
  const proxyUrl = config.proxy || process.env.AUDIT_PROXY;
  if (proxyUrl && allowedHosts.length === 0) {
    throw new Error('Proxy browser audits require an explicit RoE host allowlist');
  }

  const allowPrivate = config.allow_private === true;
  const resolveDnsLocally = !proxyUrl;
  const initialCheck = await classifyUrl(
    targetUrl,
    allowPrivate,
    allowedHosts,
    resolveDnsLocally
  );
  if (!initialCheck.ok) {
    throw new Error(`Target blocked by scope/SSRF guard: ${initialCheck.reason}`);
  }

  const timeoutMs = config.timeout_ms || 30000;
  const outDir = config.out_dir || '/workspace/reports';
  const skipWarmup = config.skip_warmup === true;
  const humanize = config.bypass_turnstile !== false;

  console.error(`[*] Launching Hardened Stealth Chromium audit against: ${targetUrl}`);
  if (proxyUrl) console.error('[*] Upstream proxy configured with explicit RoE host allowlist.');

  const launchArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--disable-gpu',
    '--disable-webrtc',
    '--disable-features=WebRtcHideLocalIpsWithMdns',
    '--enforce-webrtc-ip-permission-check',
  ];

  const browserOptions = { headless: true, args: launchArgs };
  if (proxyUrl) browserOptions.proxy = { server: proxyUrl };

  let browser;
  try {
    browser = await chromium.launch(browserOptions);
  } catch {
    browser = await chromium.launch({
      ...browserOptions,
      executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
    });
  }

  const mergedHeaders = {
    ...(config.spoof_headers || {}),
    ...(config.auth_headers || {}),
  };
  const contextOptions = {
    viewport: { width: 1440, height: 900 },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    ignoreHTTPSErrors: true,
    ...(Object.keys(mergedHeaders).length > 0 ? { extraHTTPHeaders: mergedHeaders } : {}),
  };

  const context = await browser.newContext(contextOptions);
  if (config.cookies && Array.isArray(config.cookies)) await context.addCookies(config.cookies);

  const page = await context.newPage();
  if (humanize) setupHumanCursor(page);

  await page.route('**/*', async (route) => {
    const reqUrl = route.request().url();
    const check = await classifyUrl(reqUrl, allowPrivate, allowedHosts, resolveDnsLocally);
    if (!check.ok) {
      console.error(`[RoE-Guard] Aborted forbidden destination: ${check.reason}`);
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });

  const networkRequests = [];
  const securityHeaders = {};
  let mainResponseStatus = 200;
  let turnstileDetected = false;

  page.on('response', (response) => {
    const url = response.url();
    const status = response.status();
    const headers = response.headers();
    if (url === targetUrl || url === targetUrl + '/') {
      mainResponseStatus = status;
      for (const [key, val] of Object.entries(headers)) securityHeaders[key.toLowerCase()] = val;
    }
    networkRequests.push({ url, status, method: response.request().method(), headers });
  });

  const startTime = Date.now();
  let navigationError = null;

  try {
    if (config.generate_decoy_noise === true) {
      await runDecoyBurst(2, 100, 350);
    }

    if (!skipWarmup) {
      try {
        const urlObj = new URL(targetUrl);
        const rootUrl = `${urlObj.protocol}//${urlObj.host}/`;
        if (rootUrl !== targetUrl && rootUrl !== targetUrl + '/') {
          const warmupCheck = await classifyUrl(
            rootUrl,
            allowPrivate,
            allowedHosts,
            resolveDnsLocally
          );
          if (warmupCheck.ok) {
            console.error(`[*] Performing Warmup Hop on site root: ${rootUrl}`);
            await page.goto(rootUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
            if (humanize) await humanDelay(1000, 2000);
          }
        }
      } catch {
        // Warmup is best-effort.
      }
    }

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    if (humanize) {
      await humanDelay(500, 1500);
      await humanScroll(page, 400);
    }

    const cfTurnstile = await page.$('iframe[src*="cloudflare.com/cdn-cgi/challenge-platform"]');
    if (cfTurnstile) {
      turnstileDetected = true;
      console.error('[!] Cloudflare Turnstile challenge detected on target page.');
    }
  } catch (e) {
    navigationError = e.message;
    console.error(`[!] Navigation error: ${e.message}`);
  }

  const cookies = await context.cookies();
  let localStorageData = {};
  let sessionStorageData = {};

  try {
    localStorageData = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        data[key] = localStorage.getItem(key);
      }
      return data;
    });
    sessionStorageData = await page.evaluate(() => {
      const data = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        data[key] = sessionStorage.getItem(key);
      }
      return data;
    });
  } catch {
    // Storage access can be restricted by the page.
  }

  const pageTitle = await page.title().catch(() => '');
  const htmlContent = await page.content().catch(() => '');
  const wafDetectionHits = WafDetector.detect({
    headers: securityHeaders,
    cookies,
    body: htmlContent,
    status: mainResponseStatus,
  });

  const auditReport = {
    target_url: targetUrl,
    scope_hosts: allowedHosts,
    title: pageTitle,
    duration_ms: Date.now() - startTime,
    navigation_error: navigationError,
    turnstile_challenge_present: turnstileDetected,
    waf_detection: wafDetectionHits,
    security_headers: securityHeaders,
    security_header_analysis: {
      has_csp: Boolean(securityHeaders['content-security-policy']),
      has_hsts: Boolean(securityHeaders['strict-transport-security']),
      has_x_frame_options: Boolean(securityHeaders['x-frame-options']),
      has_x_content_type_options: Boolean(securityHeaders['x-content-type-options']),
      referrer_policy: securityHeaders['referrer-policy'] || 'missing',
    },
    cookies,
    local_storage: localStorageData,
    session_storage: sessionStorageData,
    network_requests_count: networkRequests.length,
    html_snapshot_chars: htmlContent.length,
  };

  await browser.close();

  try {
    await fs.mkdir(outDir, { recursive: true });
    const auditFile = path.join(outDir, `browser_audit_${Date.now()}.json`);
    await fs.writeFile(auditFile, JSON.stringify(auditReport, null, 2), 'utf-8');
    auditReport.saved_report_path = auditFile;
  } catch {
    // Report persistence is best-effort; stdout remains authoritative.
  }

  console.log(JSON.stringify(auditReport));
}

runAudit().catch((err) => {
  console.error('[FATAL] Stealth browser execution failed:', err.message);
  process.exit(1);
});
