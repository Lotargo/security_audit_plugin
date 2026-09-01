# Example: Auditing .onion Exposure and RFC 8738 Header

```http
# Target probe response:
GET / HTTP/2
Host: example.com

HTTP/2 200 OK
Server: cloudflare
Onion-Location: http://expyuz5wqqgahqda2vg5ewvdgah5f4nk5j6smixswghesnvfdv2umqid.onion/
```

### Direct Onion Endpoint Probe
```bash
curl -s --socks5-hostname 127.0.0.1:9050 http://expyuz5wqqgahqda2vg5ewvdgah5f4nk5j6smixswghesnvfdv2umqid.onion/admin/login
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
```
**Finding:** The `.onion` endpoint bypassed Cloudflare Turnstile and WAF ACL rules, exposing the raw Apache origin server and unauthenticated administrative interface.
