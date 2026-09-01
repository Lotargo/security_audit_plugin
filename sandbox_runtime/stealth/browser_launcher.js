/**
 * browser_launcher.js - Stealth Browser Runner for DAST audits
 * Integrates playwright-extra, puppeteer-extra-plugin-stealth, Tor/Proxy routing, WebRTC disabling,
 * security header extraction, cookies & storage analysis, and DOM state inspection.
 */

import { chromium } from 'playwright-extra';
import stealthPlugin from 'puppeteer-extra-plugin-stealth';
import { setupHumanCursor, humanDelay, humanScroll } from './mouse_bezier.js';
import fs from 'fs/promises';
import path from 'path';

// Apply puppeteer-extra stealth plugin
chromium.use(stealthPlugin());

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

  console.error(`[*] Launching Stealth Chromium audit against: ${targetUrl}`);
  if (proxyUrl) {
    console.error(`[*] Upstream Proxy configured: ${proxyUrl}`);
  }

  const launchArgs = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-accelerated-2d-canvas',
    '--disable-gpu',
    // Strict Tor OPSEC: Disable WebRTC to prevent real IP leaks
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

  const networkRequests = [];
  const securityHeaders = {};
  let turnstileDetected = false;

  // Intercept responses to extract security headers and network telemetry
  page.on('response', (response) => {
    const url = response.url();
    const status = response.status();
    const headers = response.headers();

    if (url === targetUrl || url === targetUrl + '/') {
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

  const auditReport = {
    target_url: targetUrl,
    title: pageTitle,
    duration_ms: Date.now() - startTime,
    navigation_error: navigationError,
    turnstile_challenge_present: turnstileDetected,
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
    network_requests_count: networkRequests.len,
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
