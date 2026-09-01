// AST endpoint extractor script for JS bundles
const fs = require('fs');

function extractEndpoints(filePath) {
  const code = fs.readFileSync(filePath, 'utf8');
  const routeRegex = /['"`](\/(?:api|v[0-9]+|graphql|auth|user|admin)[^'"`\s]*)['"`]/g;
  const matches = new Set();
  let match;
  while ((match = routeRegex.exec(code)) !== null) {
    matches.add(match[1]);
  }
  return Array.from(matches);
}

if (process.argv[2]) {
  const endpoints = extractEndpoints(process.argv[2]);
  console.log(JSON.stringify({ file: process.argv[2], discovered_endpoints: endpoints }, null, 2));
}
