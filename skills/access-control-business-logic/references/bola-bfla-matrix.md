# OWASP API Security Access Control Reference Matrix

| Category | Description | CWE ID | Remediation Strategy |
| :--- | :--- | :--- | :--- |
| **API1: BOLA (IDOR)** | Direct object access without verifying user/tenant ownership | CWE-639 | Enforce ownership check in repository query (`WHERE id = :id AND tenant_id = :tenant`) |
| **API3: BOPLA** | Mass assignment allowing update of unauthorized attributes | CWE-915 | Use explicit DTO whitelists (Zod, Pydantic, TypeScript interfaces) |
| **API5: BFLA** | Administrative or privileged endpoints accessible by low-privilege roles | CWE-862 | Centralized RBAC middleware / Policy Engine (OPA/Rego) |
| **CWE-362 (Race Condition)** | Parallel requests bypass rate limits or consume balance multiple times | CWE-362 | Transactional isolation & database row locks (`SELECT FOR UPDATE`) |
