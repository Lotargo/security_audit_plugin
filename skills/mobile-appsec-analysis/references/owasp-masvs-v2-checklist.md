# OWASP MASVS v2.0 Standard Checklist

| Domain | Control Code | Security Requirement |
| :--- | :--- | :--- |
| **MASVS-STORAGE** | V1.1 | Sensitive data is encrypted when stored locally using platform-provided APIs. |
| **MASVS-CRYPTO** | V2.1 | The app uses proven, hardware-backed cryptographic primitives (Keystore / Keychain). |
| **MASVS-AUTH** | V3.1 | Authentication and session state are managed securely. |
| **MASVS-NETWORK** | V4.1 | All network communications use TLS and enforce Certificate Pinning on critical domains. |
| **MASVS-PLATFORM** | V5.1 | IPC mechanisms, deep links, and WebViews validate all input parameters. |
| **MASVS-CODE** | V6.1 | Debugging flags (`debuggable`), stack traces, and verbose logging are disabled in release builds. |
