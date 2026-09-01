// Script to audit response security headers
const https = require('https');
const http = require('http');

const targetUrl = process.argv[2];
if (!targetUrl) {
  console.error("Usage: node dast_header_audit.js <url>");
  process.exit(1);
}

const client = targetUrl.startsWith('https') ? https : http;

client.get(targetUrl, (res) => {
  const headers = res.headers;
  const audit = {
    url: targetUrl,
    statusCode: res.statusCode,
    csp: headers['content-security-policy'] || 'MISSING',
    hsts: headers['strict-transport-security'] || 'MISSING',
    xFrameOptions: headers['x-frame-options'] || 'MISSING',
    xContentTypeOptions: headers['x-content-type-options'] || 'MISSING',
    referrerPolicy: headers['referrer-policy'] || 'MISSING',
    cors: headers['access-control-allow-origin'] || 'NONE'
  };
  console.log(JSON.stringify(audit, null, 2));
}).on('error', (err) => {
  console.error(JSON.stringify({ error: err.message }));
});
