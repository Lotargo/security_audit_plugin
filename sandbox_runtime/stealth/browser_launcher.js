/**
 * browser_launcher.js - Stealth Browser Runner for DAST audits (Decepticon Hardened)
 * Integrates playwright-extra, puppeteer-extra-plugin-stealth, Tor/Proxy routing, WebRTC disabling,
 * In-Browser L7 SSRF guardrail, Warmup Hop sensor navigation, Multi-Signal WAF detection,
 * security header extraction, cookies & storage analysis, and DOM state inspection.
 */

import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { setupHumanCursor, humanDelay, humanScroll } from './mouse_bezier.js';
import { WafDetector } from './waf_detector.js';
import fs from 'fs/promises';
import path from 'path';
import dns from 'dns/promises';

// Apply puppeteer-extra stealth plugin
chromium.use(stealthPlugin());

/**
 * Checks if an IPv4 or IPv6 address belongs to private, loopback, link-local, or cloud metadata ranges.
 */
function isPrivateOrRestrictedIp(ipStr) {
  if (!ipStr) return true;
  const ip = ipStr.trim();

  // IPv4 Loopback & Special
  if (ip.startsWith('127.') || ip === '0.0.0.0') return true;
  // IPv4 RFC 1918 Private
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  // AWS/GCP/Azure Cloud Metadata & Link-Local
  if (ip.startsWith('169.254.')) return true;
  // CGNAT RFC 6598
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(ip)) return true;

  // IPv6 Loopback & Link-local
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) return true;
  // IPv4-mapped IPv6 / NAT64 (64:ff9b::)
  if (ip.toLowerCase().startsWith('::ffff:') || ip.toLowerCase().startsWith('64:ff9b:')) {
    const v4part = ip.split(':').pop();
    if (v4part && isPrivateOrRestrictedIp(v4part)) return true;
  }

  return false;
}

/**
 * Validates request destination against L7 SSRF guardrail before browser connects
 */
async function classifyUrl(urlStr, allowPrivate = false) {
  try {
    const parsed = new URL(urlStr);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, reason: `Unsupported protocol: ${parsed.protocol}` };
    }
    if (allowPrivate) {
      return { ok: true, reason: 'allow_private' };
    }

    const host = parsed.hostname;
    // Check if host is direct IP
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) {
      if (isPrivateOrRestrictedIp(host)) {
        return { ok: false, reason: `Direct private IP access blocked: ${host}` };
      }
    }

    // Resolve DNS records to verify resolved destination
    try {
      const records = await dns.lookup(host, { all: true });
      for (const record of records) {
        if (isPrivateOrRestrictedIp(record.address)) {
          return { ok: false, reason: `DNS resolves to restricted private IP: ${host} -> ${record.address}` };
        }
      }
    } catch (_dnsErr) {
      // Best effort DNS resolution
    }

    return { ok: true, reason: 'public' };
  } catch (err) {
    return { ok: false, reason: `URL parse error: ${err.message}` };
  }
}

/**
 * Main audit runner
 * Usage: node browser_launcher.js '<json_config>'
 */
async function runAudit() {
  const args = process.argv.slice(2);
  let config = {};

  if (args[0]) {
    try {
      config = JSON.parse(args[0]);
    } catch {
      config = { url: args[0] };
    }
  }

  const targetUrl = config.url || 'http://localhost:8080';
  const proxyUrl = config.proxy || process.env.AUDIT_PROXY;
  const timeoutMs = config.timeout_ms || 30000;
  const outDir = config.out_dir || '/workspace/reports';
  const allowPrivate = config.allow_private === true;
  const skipWarmup = config.skip_warmup === true;

  console.error(`[*] Launching Hardened Stealth Chromium audit against: ${targetUrl}`);
  if (proxyUrl) {
    console.error(`[*] Upstream Proxy configured: ${proxyUrl}`);
  }

  const launchArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--disable-gpu',
    // Strict Tor & Sandbox OPSEC: Disable WebRTC to prevent real IP leaks
    '--disable-webrtc',
    '--disable-features=WebRtcHideLocalIpsWithMdns',
    '--enforce-webrtc-ip-permission-check',
  ];

  const browserOptions = {
    headless: true,
    args: launchArgs,
  };

  if (proxyUrl) {
    browserOptions.proxy = {
      server: proxyUrl,
    };
  }

  let browser;
  try {
    browser = await chromium.launch(browserOptions);
  } catch (err) {
    // Fallback if system chromium path is used
    browser = await chromium.launch({
      ...browserOptions,
      executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
    });
  }

  const contextOptions = {
    viewport: { width: 1440, height: 900 },
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    ignoreHTTPSErrors: true,
  };

  if (config.auth_headers) {
    contextOptions.extraHTTPHeaders = config.auth_headers;
  }

  const context = await browser.newContext(contextOptions);

  if (config.cookies && Array.isArray(config.cookies)) {
    await context.addCookies(config.cookies);
  }

  const page = await context.newPage();
  const cursor = setupHumanCursor(page);

  // In-Browser L7 SSRF Guardrail
  await page.route('**/*', async (route) => {
    const reqUrl = route.request().url();
    const check = await classifyUrl(reqUrl, allowPrivate);
    if (!check.ok) {
      console.error(`[SSRF-Guard] Aborted outbound request to forbidden destination: ${reqUrl} (${check.reason})`);
      await route.abort('blockedbyclient');
      return;
    }
    await route.continue();
  });

  const networkRequests = [];
  const securityHeaders = {};
  let mainResponseStatus = 200;
  let turnstileDetected = false;

  // Intercept responses to extract security headers and network telemetry
  page.on('response', (response) => {
    const url = response.url();
    const status = response.status();
    const headers = response.headers();

    if (url === targetUrl || url === targetUrl + '/') {
      mainResponseStatus = status;
      for (const [key, val] of Object.entries(headers)) {
        securityHeaders[key.toLowerCase()] = val;
      }
    }

    networkRequests.push({
      url,
      status,
      method: response.request().method(),
      headers,
    });
  });

  const startTime = Date.now();
  let navigationError = null;

  try {
    // 1. Warmup Hop: Visit root domain first if hitting deep path (clears Akamai/Cloudflare bot sensors)
    if (!skipWarmup) {
      try {
        const urlObj = new URL(targetUrl);
        const rootUrl = `${urlObj.protocol}//${urlObj.host}/`;
        if (rootUrl !== targetUrl && rootUrl !== targetUrl + '/') {
          console.error(`[*] Performing Warmup Hop on site root: ${rootUrl}`);
          await page.goto(rootUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
          await humanDelay(1000, 2000);
        }
      } catch (_wErr) {
        // Warmup is best-effort
      }
    }

    // 2. Main Navigation
    await page.goto(targetUrl, {
      waitUntil: 'domcontentloaded',
      timeout: timeoutMs,
    });

    await humanDelay(500, 1500);

    // Natural human scrolling to trigger lazy-loaded assets
    await humanScroll(page, 400);

    // Check for Cloudflare Turnstile or challenge iframes
    const cfTurnstile = await page.$('iframe[src*="cloudflare.com/cdn-cgi/challenge-platform"]');
    if (cfTurnstile) {
      turnstileDetected = true;
      console.error('[!] Cloudflare Turnstile challenge detected on target page.');
    }
  } catch (e) {
    navigationError = e.message;
    console.error(`[!] Navigation error: ${e.message}`);
  }

  // Extract cookies and storage
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
  } catch (e) {
    // Storage access might be restricted
  }

  const pageTitle = await page.title().catch(() => '');
  const htmlContent = await page.content().catch(() => '');

  // Run Multi-Signal WAF Detection on collected evidence
  const wafDetectionHits = WafDetector.detect({
    headers: securityHeaders,
    cookies,
    body: htmlContent,
    status: mainResponseStatus,
  });

  const auditReport = {
    target_url: targetUrl,
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

  // Save report to workspace if available
  try {
    await fs.mkdir(outDir, { recursive: true });
    const auditFile = path.join(outDir, `browser_audit_${Date.now()}.json`);
    await fs.writeFile(auditFile, JSON.stringify(auditReport, null, 2), 'utf-8');
    auditReport.saved_report_path = auditFile;
  } catch (e) {
    // Fallback if outDir not writable
  }

  // Output JSON report to stdout for calling agent/daemon
  console.log(JSON.stringify(auditReport, null, 2));
}

runAudit().catch((err) => {
  console.error('[FATAL] Stealth browser execution failed:', err);
  process.exit(1);
});
