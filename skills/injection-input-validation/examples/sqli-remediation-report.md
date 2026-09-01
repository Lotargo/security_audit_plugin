# Example Injection Vulnerability Report: SQL Injection

### Finding Details
- **Title:** Unescaped Dynamic SQL in Product Filter Parameter
- **Severity:** High (CVSS 8.6)
- **CWE:** CWE-89 (SQL Injection)

### Vulnerable Source Code
```typescript
// src/controllers/product.ts
export async function getProducts(req: Request, res: Response) {
  const sortBy = req.query.sort || 'id';
  // String concatenation into SQL query!
  const query = `SELECT * FROM products WHERE active = 1 ORDER BY ${sortBy}`;
  const rows = await db.query(query);
  res.json(rows);
}
```

### Hardened Implementation
```typescript
const ALLOWED_SORT_COLUMNS = new Set(['id', 'price', 'created_at', 'title']);

export async function getProducts(req: Request, res: Response) {
  const rawSort = String(req.query.sort || 'id');
  const sortBy = ALLOWED_SORT_COLUMNS.has(rawSort) ? rawSort : 'id';
  
  const query = `SELECT id, price, created_at, title FROM products WHERE active = 1 ORDER BY ${sortBy}`;
  const rows = await db.query(query);
  res.json(rows);
}
```
