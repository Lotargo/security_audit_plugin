# Network Zone Segmentation & Compliance Reference

| Source Zone | Destination Zone | Permitted Protocols | Blocked Protocols (Violation) |
| :--- | :--- | :--- | :--- |
| **Office LAN** | **Production Web** | HTTPS (443) | SSH (22), RDP (3389), Direct DB (5432, 3306) |
| **Office LAN** | **PCI DSS (CDE)** | None (Strict Bastion only) | Any direct connection (PCI DSS Req 1.3 failure) |
| **DMZ / Ingress** | **Database Tier** | Scoped DB Port (e.g., 5432) | SMB (445), SSH (22), Management APIs |
| **Development** | **Production** | None (Isolated VPC) | Any direct routing |
