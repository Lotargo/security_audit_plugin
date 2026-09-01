// Script to probe rate limit with header spoofing
const http = require('http');
const https = require('https');

const url = process.argv[2];
if (!url) {
  console.error("Usage: node probe_rate_limit.js <url>");
  process.exit(1);
}

async function sendProbe(spoofedIp) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === 'https:' ? https : http;
    const req = client.request(url, {
      method: 'GET',
      headers: {
        'X-Forwarded-For': spoofedIp,
        'User-Agent': 'SecurityAuditProbe/1.0'
      }
    }, (res) => {
      resolve({ ip: spoofedIp, status: res.statusCode });
    });
    req.on('error', (e) => resolve({ ip: spoofedIp, error: e.message }));
    req.end();
  });
}

(async () => {
  const results = [];
  for (let i = 1; i <= 5; i++) {
    const res = await sendProbe(`198.51.100.${i}`);
    results.push(res);
  }
  console.log(JSON.stringify(results, null, 2));
})();
