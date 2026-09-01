/**
 * mouse_bezier.js - Humanized mouse movement and typing simulator
 * Emulates cubic Bezier curves with natural jitter, acceleration/deceleration and human typing latencies
 * to bypass bot detection (Cloudflare Turnstile, DataDome, Akamai).
 */

import { createCursor } from 'ghost-cursor';

/**
 * Creates a human cursor controller attached to the Playwright page
 * @param {import('playwright-core').Page} page
 */
export function setupHumanCursor(page) {
  const cursor = createCursor(page);
  return cursor;
}

/**
 * Natural human delay with random jitter
 * @param {number} minMs
 * @param {number} maxMs
 */
export async function humanDelay(minMs = 150, maxMs = 450) {
  const delay = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  await new Promise((resolve) => setTimeout(resolve, delay));
}

/**
 * Simulates human typing with variable keypress intervals and occasional pauses
 * @param {import('playwright-core').Page} page
 * @param {string} selector
 * @param {string} text
 */
export async function humanType(page, selector, text) {
  const element = page.locator(selector).first();
  await element.focus();
  await humanDelay(100, 250);

  for (const char of text) {
    await page.keyboard.type(char);
    // Keypress interval between 35ms and 110ms
    const keyDelay = Math.floor(Math.random() * 75) + 35;
    await new Promise((r) => setTimeout(r, keyDelay));

    // 5% chance of a micro hesitation pause (150-300ms)
    if (Math.random() < 0.05) {
      await humanDelay(150, 300);
    }
  }
  await humanDelay(100, 300);
}

/**
 * Natural scroll with random steps and deceleration
 * @param {import('playwright-core').Page} page
 * @param {number} scrollDelta
 */
export async function humanScroll(page, scrollDelta = 500) {
  const steps = 6;
  const stepDelta = scrollDelta / steps;

  for (let i = 0; i < steps; i++) {
    const jitter = (Math.random() - 0.5) * 20;
    await page.mouse.wheel(0, stepDelta + jitter);
    await humanDelay(30, 80);
  }
}
