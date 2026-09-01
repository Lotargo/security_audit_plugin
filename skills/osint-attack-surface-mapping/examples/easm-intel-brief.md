# Example OSINT & EASM Intelligence Brief

### Target: `acme-corp.com`

## 1. Domain & Email Authentication Posture
- **SPF:** `v=spf1 include:mailgun.org ~all` -> *Weak Softfail*
- **DMARC:** `v=DMARC1; p=none; rua=mailto:dmarc@acme-corp.com` -> *Inactive Enforcement (p=none)*
- **Risk:** High - Domain vulnerable to email spoofing.

## 2. Discovered Subdomains & Takeover Exposures
| Subdomain | CNAME Target | Status |
| :--- | :--- | :--- |
| `docs.acme-corp.com` | `acme-docs.github.io` | **VULNERABLE:** Dangling CNAME to unclaimed GitHub Pages repo |
| `api.acme-corp.com` | `aws-elb-12345.us-east-1.elb.amazonaws.com` | Active API Gateway |
