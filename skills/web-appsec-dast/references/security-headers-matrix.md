# HTTP Security Headers & CORS Reference Matrix

| Header | Recommended Baseline Value | Insecure Configuration | Risk / CWE |
| :--- | :--- | :--- | :--- |
| **Content-Security-Policy** | `default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; frame-ancestors 'none';` | `'unsafe-inline'`, `'unsafe-eval'`, `https:*` wildcard | XSS, Clickjacking (CWE-79, CWE-1021) |
| **Strict-Transport-Security** | `max-age=63072000; includeSubDomains; preload` | Missing or `max-age=0` | SSL Stripping, MITM (CWE-319) |
| **X-Content-Type-Options** | `nosniff` | Missing | MIME-type Sniffing (CWE-79) |
| **X-Frame-Options** | `DENY` or `SAMEORIGIN` | Missing | Clickjacking (CWE-1021) |
| **Referrer-Policy** | `strict-origin-when-cross-origin` | `unsafe-url`, `no-referrer-when-downgrade` | Sensitive URL/Token Leakage (CWE-200) |
| **Access-Control-Allow-Origin** | Explicit origin (e.g. `https://app.example.com`) | `*` (with credentials) or reflected Origin | CORS Misconfiguration (CWE-942) |
