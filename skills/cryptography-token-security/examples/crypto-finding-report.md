# Example Cryptographic Audit Finding: JWT Algorithm Confusion

### Finding Details
- **Title:** JWT Algorithm Confusion (RS256 vs HS256) Allows Signature Forgery
- **Severity:** Critical (CVSS 9.8)
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **Reference:** RFC 8725 Section 3.1

### Vulnerable Implementation
```python
# Vulnerable JWT verification
def verify_token(token, public_key_pem):
    # Missing explicit algorithms parameter!
    payload = jwt.decode(token, public_key_pem)
    return payload
```

### Attack Mechanics
An attacker signs a token using the server's public RSA key (which is publicly available) as an HMAC secret with `alg: HS256`. The vulnerable parser reads `HS256` from the header and uses the `public_key_pem` string as the symmetric secret, successfully validating the forged token.

### Hardened Implementation
```python
def verify_token(token, public_key_pem):
    payload = jwt.decode(
        token,
        public_key_pem,
        algorithms=["RS256"],  # Strict algorithm whitelist
        options={"require": ["exp", "iss", "aud"]}
    )
    return payload
```
