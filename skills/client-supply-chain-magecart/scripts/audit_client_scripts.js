// Script to parse HTML and verify script SRI and provenance
const fs = require('fs');

const htmlFile = process.argv[2];
if (!htmlFile) {
  console.error("Usage: node audit_client_scripts.js <html_file>");
  process.exit(1);
}

const content = fs.readFileSync(htmlFile, 'utf8');
const scriptRegex = /<script\b([^>]*)>/gi;
let match;
const findings = [];

while ((match = scriptRegex.exec(content)) !== null) {
  const attrs = match[1];
  const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
  if (srcMatch) {
    const src = srcMatch[1];
    const hasIntegrity = /integrity=/i.test(attrs);
    const hasCrossOrigin = /crossorigin=/i.test(attrs);
    const isThirdParty = src.startsWith('http://') || src.startsWith('https://') || src.startsWith('//');

    findings.push({
      src,
      isThirdParty,
      hasIntegrity,
      hasCrossOrigin,
      risk: (isThirdParty && !hasIntegrity) ? "HIGH: Third-party script without SRI hash" : "OK"
    });
  }
}

console.log(JSON.stringify(findings, null, 2));
