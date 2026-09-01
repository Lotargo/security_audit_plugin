/**
 * decoy_traffic.js - Background Noise & Decoy Traffic Generator
 * Intersperses realistic benign browser traffic (Google Fonts, favicons, static CDN assets, analytics pings)
 * to blur the audit footprint and evade SIEM/WAF behavioural anomaly detection.
 */

import http from 'http';
import https from 'https';

const BENIGN_ASSET_TARGETS = [
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
];

/**
 * Sends a lightweight GET request mimicking background browser asset fetching
 * @param {string} targetUrl
 */
function fetchDecoyAsset(targetUrl) {
  return new Promise((resolve) => {
    try {
      const urlObj = new URL(targetUrl);
      const client = urlObj.protocol === 'https:' ? https : http;

      const req = client.get(
        targetUrl,
        {
          headers: {
            'User-Agent':
              'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            Accept: 'text/css,*/*;q=0.1',
            'Accept-Language': 'en-US,en;q=0.9',
            'Sec-Fetch-Dest': 'style',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'cross-site',
          },
          timeout: 5000,
        },
        (res) => {
          res.resume(); // Discard response data
          res.on('end', () => resolve(true));
        }
      );

      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
    } catch {
      resolve(false);
    }
  });
}

/**
 * Runs a continuous decoy traffic loop with random jitter intervals
 * @param {number} count
 * @param {number} minDelayMs
 * @param {number} maxDelayMs
 */
export async function runDecoyBurst(count = 5, minDelayMs = 500, maxDelayMs = 2000) {
  console.error(`[*] Emitting ${count} decoy background traffic requests...`);
  for (let i = 0; i < count; i++) {
    const target = BENIGN_ASSET_TARGETS[i % BENIGN_ASSET_TARGETS.length];
    await fetchDecoyAsset(target);
    const delay = Math.floor(Math.random() * (maxDelayMs - minDelayMs + 1)) + minDelayMs;
    await new Promise((r) => setTimeout(r, delay));
  }
  console.error('[*] Decoy traffic burst complete.');
}

// If executed directly
if (process.argv[1] && process.argv[1].endsWith('decoy_traffic.js')) {
  const burstCount = parseInt(process.argv[2] || '5', 10);
  runDecoyBurst(burstCount).catch(console.error);
}
