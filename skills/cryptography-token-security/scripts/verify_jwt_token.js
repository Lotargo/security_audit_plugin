// Script to inspect JWT token headers and claims without signature verification
const token = process.argv[2];
if (!token) {
  console.error("Usage: node verify_jwt_token.js <jwt_string>");
  process.exit(1);
}

try {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format (expected 3 parts)");
  }
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

  const analysis = {
    header,
    payload,
    risks: []
  };

  if (header.alg === 'none' || header.alg === 'NONE') {
    analysis.risks.push("CRITICAL: Token uses 'none' algorithm");
  }
  if (!payload.exp) {
    analysis.risks.push("HIGH: Missing 'exp' (expiration) claim");
  } else if (Date.now() / 1000 > payload.exp) {
    analysis.risks.push("INFO: Token is expired");
  }
  if (header.jku) {
    analysis.risks.push(`WARNING: Header contains 'jku' parameter: ${header.jku}`);
  }

  console.log(JSON.stringify(analysis, null, 2));
} catch (e) {
  console.error(JSON.stringify({ error: e.message }));
}
