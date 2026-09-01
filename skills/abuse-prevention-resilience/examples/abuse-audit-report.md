# Example Abuse & Resilience Audit Report

### Finding Details
- **Title:** Rate-Limit Bypass on Password Reset via L7 `X-Forwarded-For` Header Spoofing
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-290 (Authentication Bypass by Spoofing), CWE-307 (Improper Restriction of Excessive Authentication Attempts)

### Technical Description
The `/api/v1/auth/forgot-password` endpoint uses the client-supplied `X-Forwarded-For` header to calculate the rate limit key:
```javascript
const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
await rateLimiter.consume(clientIp);
```
An attacker can iterate random IP strings in `X-Forwarded-For: 1.2.3.<n>` with each request, completely bypassing the rate limiter to trigger thousands of password reset emails.

### Remediation
Enforce client IP resolution from trusted upstream proxy socket address only:
```javascript
const clientIp = req.socket.remoteAddress; // Or use proxy-addr with trusted reverse proxy subnet
```
