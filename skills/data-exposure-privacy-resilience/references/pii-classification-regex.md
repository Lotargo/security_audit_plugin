# Sensitive Data & Secret Detection Patterns

| Category | Regex Pattern | Description |
| :--- | :--- | :--- |
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` | 20-character AWS Access Key ID |
| **AWS Secret Key** | `(?i)aws(.{0,20})?(?-i)['"][0-9a-zA-Z\/+]{40}['"]` | 40-character base64 secret |
| **Private Key Header** | `-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----` | Unencrypted PEM private key |
| **Generic API Token** | `(?i)(api[_-]?key|auth[_-]?token|secret)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]` | High-entropy authentication token |
| **Credit Card Number** | `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b` | Visa, Mastercard, AMEX (validate with Luhn) |
| **Social Security Number** | `\b\d{3}-\d{2}-\d{4}\b` | US SSN format |
