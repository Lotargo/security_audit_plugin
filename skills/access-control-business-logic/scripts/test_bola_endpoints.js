// Script to compare dual-token access responses across an endpoint
const http = require('http');
const https = require('https');

const [,, url, tokenA, tokenB] = process.argv;
if (!url || !tokenA || !tokenB) {
  console.error("Usage: node test_bola_endpoints.js <endpoint_url> <token_userA> <token_userB>");
  process.exit(1);
}

function fetchWithToken(token) {
  return new Promise((resolve) => {
    const urlObj = new URL(url);
    const client = urlObj.protocol === 'https:' ? https : http;
    const req = client.request(url, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${token}` }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ status: res.statusCode, bodyLength: body.length }));
    });
    req.on('error', e => resolve({ error: e.message }));
    req.end();
  });
}

(async () => {
  const resA = await fetchWithToken(tokenA);
  const resB = await fetchWithToken(tokenB);
  console.log(JSON.stringify({ endpoint: url, userA_response: resA, userB_response: resB }, null, 2));
})();
