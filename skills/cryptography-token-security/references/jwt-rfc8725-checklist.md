# RFC 8725 JWT Security Best Current Practices Checklist

1. **Algorithm Validation**:
   - Explicitly specify allowed algorithms (e.g., `algorithms: ['RS256']`). Never dynamically read `alg` from token header to select verification cipher.
   - Strictly disallow `none`, `None`, `NONE`.

2. **Key Confusion Prevention**:
   - Prevent asymmetric public keys (PEM strings) from being treated as HMAC secret keys when `alg: HS256` is provided.

3. **Header Parameter Safeguards**:
   - Disallow unauthenticated `jku` (JWK Set URL) and `jwk` parameter loading from untrusted domains.
   - JWKS endpoints must be pinned to explicit HTTPS URLs.

4. **Claims Verification**:
   - Validate `exp` (Expiration) is present and within TTL.
   - Validate `iss` (Issuer) and `aud` (Audience) match exact expected values.
