# Web Cache Poisoning & Unkeyed Headers Catalogue

| Header | Intended Purpose | Poisoning Mechanism |
| :--- | :--- | :--- |
| `X-Forwarded-Host` | Identifies original host requested by client | Reflected in `<script src="https://{{X-Forwarded-Host}}/app.js">` |
| `X-Forwarded-Scheme` / `X-Forwarded-Proto` | Informs backend of client protocol (HTTP/HTTPS) | Triggers redirect `301 Location: https://...` cached for all HTTP clients |
| `X-Original-URL` / `X-Rewrite-URL` | Custom routing override in some reverse proxies | Changes response body to target URL while cached under original URL key |
| `X-Host` / `Host-Override` | Legacy host header override | Host header injection leading to password reset poisoning in cache |
