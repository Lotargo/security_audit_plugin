# Example HTTP Smuggling Audit Finding: CL.TE Desynchronization

### Finding Details
- **Title:** HTTP Request Smuggling (CL.TE) via Ambiguous Transfer-Encoding
- **Severity:** Critical (CVSS 9.3)
- **RFC Ref:** RFC 9112 Section 6.3
- **CWE:** CWE-444 (Inconsistent Interpretation of HTTP Requests)

### Technical Request Payload
```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Frontend proxy forwards 13 bytes according to `Content-Length`. Backend processes `0\r\n\r\n` as end of chunked body, leaving `SMUGGLED` in socket buffer to prepend to the next user's HTTP request.

### Hardened Proxy Configuration (Nginx)
```nginx
# Reject ambiguous headers and enable HTTP/2 end-to-end
server {
    listen 443 ssl http2;
    ignore_invalid_headers on;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}
```
