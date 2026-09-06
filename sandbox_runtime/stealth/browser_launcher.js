/**
 * Hardened Playwright browser runner for DAST audits.
 * Config is accepted either as legacy argv JSON/URL or, preferably, via --stdin-json so
 * authentication headers and cookies do not appear in the process list.
 */

import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { setupHumanCursor, humanDelay, humanScroll } from './mouse_bezier.js';
import { WafDetector } from './waf_detector.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import {
  classifyUrl,
  normalizeHost,
  normalizeAllowedHosts,
  isPrivateOrRestrictedIp,
} from './browser_guard.js';

chromium.use(stealthPlugin());

export { classifyUrl, normalizeHost, normalizeAllowedHosts, isPrivateOrRestrictedIp };

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

export async function runAudit() {
  const config = await readConfig();
  const targetUrl = config.url;
  if (!targetUrl) throw new Error('Browser audit config is missing url');

  const allowedHosts = normalizeAllowedHosts(config.allowed_hosts);
  const proxyUrl = config.proxy || process.env.AUDIT_PROXY;
  const isTor = Boolean(
    config.is_tor ||
    (proxyUrl && (proxyUrl.includes('9050') || proxyUrl.includes('tor')))
  );

  if (proxyUrl && allowedHosts.length === 0) {
    throw new Error('Proxy browser audits require an explicit RoE host allowlist');
  }

  const allowPrivate = config.allow_private === true;
  const initialCheck = await classifyUrl(targetUrl, allowPrivate, allowedHosts, isTor);
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
    '--enable-logging=stderr',
    '--v=1',
    '--disable-crash-reporter',
    '--disable-crashpad',
    '--crash-dumps-dir=/tmp',
    '--no-crash-upload',
    '--disable-webrtc',
    '--disable-features=WebRtcHideLocalIpsWithMdns',
    '--enforce-webrtc-ip-permission-check',
  ];

  const chromiumExecutable =
    process.env.CHROMIUM_PATH ||
    (await fs
      .stat('/usr/lib/chromium/chromium')
      .then(() => '/usr/lib/chromium/chromium')
      .catch(() => '/usr/bin/chromium'));

  const browserOptions = {
    headless: true,
    args: launchArgs,
    executablePath: chromiumExecutable,
  };
  if (proxyUrl) browserOptions.proxy = { server: proxyUrl };

  const browser = await chromium.launch(browserOptions);

  const mergedHeaders = {
    ...(config.spoof_headers || {}),
    ...(config.auth_headers || {}),
  };
  const contextOptions = {
    viewport: { width: 1440, height: 900 },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    ignoreHTTPSErrors: true,
    serviceWorkers: 'block',
    ...(Object.keys(mergedHeaders).length > 0 ? { extraHTTPHeaders: mergedHeaders } : {}),
  };

  const context = await browser.newContext(contextOptions);
  if (config.cookies && Array.isArray(config.cookies)) await context.addCookies(config.cookies);

  const page = await context.newPage();
  if (humanize) setupHumanCursor(page);

  await page.route('**/*', async (route) => {
    const request = route.request();
    const reqUrl = request.url();
    const check = await classifyUrl(reqUrl, allowPrivate, allowedHosts, isTor);
    if (!check.ok) {
      console.error(
        `[RoE-Guard] Aborted forbidden destination (${request.resourceType()} -> ${reqUrl}): ${check.reason}`
      );
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
      console.error(
        '[RoE-Guard] Decoy traffic suppressed in hardened strict-scope mode; no global egress exception is permitted.'
      );
    }

    if (!skipWarmup) {
      try {
        const urlObj = new URL(targetUrl);
        const rootUrl = `${urlObj.protocol}//${urlObj.host}/`;
        if (rootUrl !== targetUrl && rootUrl !== targetUrl + '/') {
          const warmupCheck = await classifyUrl(rootUrl, allowPrivate, allowedHosts, isTor);
          if (warmupCheck.ok) {
            console.error(`[*] Performing Warmup Hop on site root: ${rootUrl}`);
            await page.goto(rootUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
            if (humanize) await humanDelay(1000, 2000);
          } else {
            console.error(`[RoE-Guard] Warmup Hop skipped: site root ${rootUrl} is outside scope`);
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

if (
  process.argv[1] &&
  (process.argv[1].endsWith('browser_launcher.js') || process.argv[1].endsWith('browser_launcher.mjs'))
) {
  runAudit().catch((err) => {
    console.error('[FATAL] Stealth browser execution failed:', err.message);
    process.exit(1);
  });
}
