# Example Network Segmentation Audit Finding: Direct LAN to DB Access

### Finding Details
- **Title:** Direct Unrestricted Access from Corporate LAN to Production Database
- **Severity:** High (CVSS 8.2)
- **Standard:** PCI DSS v4.0 Requirement 1.3 / CIS Control 12
- **CWE:** CWE-284 (Improper Access Control)

### Technical Analysis
Firewall rule #104 allows unrestricted TCP traffic on port 5432 from `10.10.0.0/16` (User Workstations) to `10.50.1.20` (Production PostgreSQL Database). Any compromised workstation on the corporate network can directly attempt brute-forcing database credentials or access database tables without passing through the bastion host or application tier.

### Remediation (iptables / Firewall Policy)
```bash
# Drop direct traffic from Workstations to Database Subnet
iptables -A FORWARD -s 10.10.0.0/16 -d 10.50.1.20 -p tcp --dport 5432 -j DROP
```
Enforce connection strictly from application servers (`10.50.2.0/24`) only.
