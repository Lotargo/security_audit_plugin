# Example Access Control Audit Report: Cross-Tenant BOLA

### Finding Details
- **Title:** BOLA (IDOR) Allows Cross-Tenant Invoice Data Access
- **Severity:** Critical (CVSS 9.1)
- **OWASP:** API1:2023 – Broken Object Level Authorization
- **CWE:** CWE-639

### Vulnerable Code
```typescript
// src/routes/invoices.ts
app.get('/api/v1/invoices/:id', async (req, res) => {
  const invoice = await db.invoices.findUnique({
    where: { id: req.params.id } // Missing tenant_id filter!
  });
  if (!invoice) return res.status(404).send();
  res.json(invoice);
});
```

### Hardened Implementation
```typescript
app.get('/api/v1/invoices/:id', async (req, res) => {
  const tenantId = req.user.tenantId; // From verified session JWT
  const invoice = await db.invoices.findFirst({
    where: {
      id: req.params.id,
      tenantId: tenantId // Strictly scoped to authenticated tenant
    }
  });
  if (!invoice) return res.status(404).send();
  res.json(invoice);
});
```
