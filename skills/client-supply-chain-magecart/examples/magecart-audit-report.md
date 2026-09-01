# Example Client Supply Chain Audit Finding

### Finding Details
- **Title:** Unversioned Third-Party Chat Widget without SRI Loaded on Payment Page
- **Severity:** High (CVSS 7.8)
- **Standard:** PCI DSS v4.0 Requirement 6.4.3
- **CWE:** CWE-353 (Missing Support for Integrity Check)

### Technical Description
The checkout payment page loads an unversioned third-party live chat script without Subresource Integrity hashes:
```html
<script src="https://widget.external-chat.com/support.js"></script>
```
If the third-party chat CDN is compromised, attackers can inject arbitrary keyloggers to capture customer card numbers directly from DOM input fields.

### Hardened Implementation
1. Pin script to explicit immutable version and add SRI hash:
```html
<script 
  src="https://widget.external-chat.com/v3.1.2/support.min.js" 
  integrity="sha384-..." 
  crossorigin="anonymous">
</script>
```
2. Restrict script loading to non-payment pages or enforce strict CSP.
