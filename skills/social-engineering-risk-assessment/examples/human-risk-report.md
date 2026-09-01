# Example Human Risk Assessment Report: IT Helpdesk MFA Reset

### Finding Details
- **Title:** IT Helpdesk Lacks Multi-Factor Verification for Employee MFA Resets
- **Severity:** High (CVSS 7.4)
- **CWE:** CWE-287 (Improper Authentication)

### Technical Analysis
The IT Service Desk standard operating procedure permits resetting employee MFA tokens and issuing temporary access passes upon receiving a phone call where the caller provides the employee's name and employee badge ID. Because badge numbers are frequently exposed in internal ticketing tools, an attacker can trivially impersonate employees to take over accounts.

### Hardened SOP
Mandate Out-of-Band manager video verification or FIDO2 hardware security key enrollment through a secure in-person or cryptographically signed workflow.
