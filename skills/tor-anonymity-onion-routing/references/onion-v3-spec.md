# Tor v3 & RFC 8738 Onion-Location Specification

## Tor v3 Onion Addressing
- Addresses are 56 base32 characters followed by `.onion` (e.g. `http://expyuz5wqqgahqda2vg5ewvdgah5f4nk5j6smixswghesnvfdv2umqid.onion`).
- Key type: Ed25519 public key embedded directly in the address.
- Encryption: Curve25519 for end-to-end circuit encryption.

## RFC 8738 (HTTP Onion-Location Header)
- Format: `Onion-Location: <onion-uri>`
- Equivalence: When a public site advertises `Onion-Location`, clients may seamlessly switch transport to the `.onion` address.
- Security Audit Implication: Many sites misconfigure the `.onion` backend to bypass Cloudflare/WAF rate limits, captcha checks, or IP ACLs.
