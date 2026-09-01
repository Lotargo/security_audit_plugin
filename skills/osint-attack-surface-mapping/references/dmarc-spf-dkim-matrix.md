# Email Security & Domain Authentication Reference Matrix

| Protocol | Secure Standard Value | Vulnerable / Weak Setting | Risk |
| :--- | :--- | :--- | :--- |
| **SPF** | `v=spf1 include:_spf.example.com -all` (Hardfail) | `+all` (allow all) or `~all` (softfail) | Direct email sender spoofing |
| **DMARC** | `v=DMARC1; p=reject; sp=reject; rua=mailto:...` | `p=none` (monitoring only) or missing | Spoofed emails delivered directly to inboxes |
| **DKIM** | 2048-bit RSA key rotated regularly | Missing or < 1024-bit key | Signature forgery |
| **DNSSEC** | Active signed zones | Missing | DNS cache poisoning / spoofing |
