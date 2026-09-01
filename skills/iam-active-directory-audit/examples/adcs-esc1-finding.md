# Example AD CS Audit Finding: ESC1 Misconfiguration

### Finding Details
- **Title:** AD CS Certificate Template Allows Domain Admin Impersonation (ESC1)
- **Severity:** Critical (CVSS 9.8)
- **Standard:** Certified Pre-Owned AD CS Benchmark (ESC1)
- **CWE:** CWE-287 (Improper Authentication)

### Technical Analysis
Certificate template `Corporate-UserAuth` has the following properties:
- **Client Authentication EKU:** `1.3.6.1.5.5.7.3.2`
- **Supply Subject:** `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled
- **Enrollment Permissions:** `Domain Users` granted `Enroll` permission
- **Manager Approval:** Disabled

Any domain user can request a certificate under this template, supplying `administrator@corp.local` as the Subject Alternative Name (SAN), and use the certificate to authenticate via PKINIT Kerberos as Domain Admin.

### Hardened Remediation
1. Disable `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` on the template (set subject to be built from Active Directory).
2. Require CA certificate manager approval before issuance.
