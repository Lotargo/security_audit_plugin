/**
 * waf_detector.js - Multi-Signal WAF & Anti-Bot Fingerprinting Engine
 * Analyzes HTTP responses (cookies, headers, server banner, body markers)
 * and returns ranked vendor detection hits with actionable evasion strategies.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PROFILES_PATH = path.join(__dirname, 'waf_profiles.json');

let cachedProfiles = null;

function loadProfiles() {
  if (cachedProfiles) return cachedProfiles;
  try {
    const raw = fs.readFileSync(PROFILES_PATH, 'utf-8');
    cachedProfiles = JSON.parse(raw);
  } catch (err) {
    console.error(`[WafDetector] Warning: Could not read ${PROFILES_PATH}, using fallback`, err);
    cachedProfiles = {};
  }
  return cachedProfiles;
}

function matchPattern(haystackList, patternList) {
  const hits = [];
  const lowerHaystacks = haystackList.map((s) => s.toLowerCase());

  for (const pat of patternList || []) {
    const patLower = pat.toLowerCase();
    if (patLower.includes('*')) {
      const regexStr = '^' + patLower.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
      const regex = new RegExp(regexStr);
      for (const item of lowerHaystacks) {
        if (regex.test(item)) {
          hits.push(pat);
          break;
        }
      }
    } else {
      if (lowerHaystacks.includes(patLower)) {
        hits.push(pat);
      }
    }
  }
  return hits;
}

export class WafDetector {
  /**
   * Evaluates response signals and returns a sorted array of DetectionHits
   * @param {Object} response
   * @param {Record<string, string>} response.headers
   * @param {Array<{name: string, value: string}>|string[]} response.cookies
   * @param {string} response.body
   * @param {number} [response.status]
   * @returns {Array<{profile_id: string, name: string, confidence: number, signals: string[], strategy: any}>}
   */
  static detect({ headers = {}, cookies = [], body = '', status = 200 }) {
    const profiles = loadProfiles();
    const hits = [];

    // Normalize inputs
    const headerKeys = Object.keys(headers || {});
    const headerServer = (headers['server'] || headers['Server'] || '').toLowerCase();
    
    let cookieNames = [];
    if (Array.isArray(cookies)) {
      cookieNames = cookies.map((c) => (typeof c === 'string' ? c.split('=')[0].trim() : c.name || ''));
    } else if (typeof cookies === 'object') {
      cookieNames = Object.keys(cookies);
    }
    
    // Also parse cookies from set-cookie header if present
    const setCookie = headers['set-cookie'] || headers['Set-Cookie'] || '';
    if (setCookie) {
      const parsedFromHeader = String(setCookie).split(/[,;]/).map(s => s.split('=')[0].trim());
      cookieNames.push(...parsedFromHeader);
    }

    const bodyLower = String(body || '').toLowerCase();

    for (const [profileId, profile] of Object.entries(profiles)) {
      if (profileId.startsWith('_') || profileId === 'unknown_challenge') continue;

      const detectors = profile.detectors || {};
      const signals = [];

      // 1. Cookie check
      if (detectors.cookie && detectors.cookie.length > 0) {
        const matched = matchPattern(cookieNames, detectors.cookie);
        matched.forEach((c) => signals.push(`cookie:${c}`));
      }

      // 2. Header check
      if (detectors.header && detectors.header.length > 0) {
        const matched = matchPattern(headerKeys, detectors.header);
        matched.forEach((h) => signals.push(`header:${h}`));
      }

      // 3. Server header substring check
      if (detectors.server_contains && detectors.server_contains.length > 0) {
        for (const needle of detectors.server_contains) {
          if (headerServer.includes(needle.toLowerCase())) {
            signals.push(`server:${needle}`);
          }
        }
      }

      // 4. Body markers
      if (detectors.body && detectors.body.length > 0) {
        for (const marker of detectors.body) {
          if (bodyLower.includes(marker.toLowerCase())) {
            signals.push(`body:${marker}`);
          }
        }
      }

      if (signals.length > 0) {
        const rules = profile.confidence_rules || { strong: 2, weak: 1 };
        let confidence = 0.3;
        if (signals.length >= (rules.strong || 2)) {
          confidence = 0.9;
        } else if (signals.length >= (rules.weak || 1)) {
          confidence = 0.6;
        }

        hits.push({
          profile_id: profileId,
          name: profile.name || profileId,
          confidence,
          signals,
          capabilities_needed: profile.capabilities_needed || [],
          strategy: profile.evasion_strategy || {},
        });
      }
    }

    // Sort by confidence descending
    hits.sort((a, b) => b.confidence - a.confidence);

    if (hits.length === 0 && (status === 403 || status === 429 || status === 503)) {
      const unknown = profiles['unknown_challenge'] || {};
      hits.push({
        profile_id: 'unknown_challenge',
        name: unknown.name || 'Generic Anti-Bot Challenge',
        confidence: 0.2,
        signals: [`http_status:${status}`],
        capabilities_needed: unknown.capabilities_needed || ['needs_js_exec'],
        strategy: unknown.evasion_strategy || {},
      });
    }

    return hits;
  }
}
