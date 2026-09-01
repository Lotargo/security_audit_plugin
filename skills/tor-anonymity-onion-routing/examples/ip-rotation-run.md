# Example: Tor Dynamic IP Rotation on WAF Challenge

```bash
# 1. Initial request triggers 429 Too Many Requests
$ curl -s -I --socks5-hostname 127.0.0.1:9050 https://target.example.com/api/v1/auth
HTTP/2 429 Too Many Requests
Retry-After: 60

# 2. Agent invokes sandbox_rotate_tor_ip tool
# Sandbox daemon sends SIGNAL NEWNYM to Tor ControlPort :9051

# 3. Verify new egress IP
$ curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
{"IsTor":true,"IP":"185.220.101.5"}

# 4. Re-probe target with new IP
$ curl -s -I --socks5-hostname 127.0.0.1:9050 https://target.example.com/api/v1/auth
HTTP/2 200 OK
```
