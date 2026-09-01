# Example DAST Vulnerability Report: DOM XSS via PostMessage

### Finding Details
- **Title:** Unvalidated `window.postMessage` Event Listener Leads to DOM XSS
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
- **OWASP:** A03:2021 – Injection

### Technical Description
The target application registers a global message handler without verifying the message origin:
```javascript
window.addEventListener('message', (e) => {
  document.getElementById('content').innerHTML = e.data.html; // Unvalidated origin and sink
});
```

### Steps to Reproduce
1. Host an external malicious page embedding the target inside an `<iframe>`.
2. Post message payload: `iframe.contentWindow.postMessage({ html: '<img src=x onerror=alert(1)>' }, '*');`
3. Observer execution of arbitrary JavaScript in the context of the target application.

### Remediation
Ensure strict origin checking before processing message data:
```javascript
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://trusted.example.com') return;
  document.getElementById('content').textContent = e.data.text;
});
```
