# Example Data Exposure Audit Finding: AWS Credentials in Logging Middleware

### Finding Details
- **Title:** Plaintext AWS Credentials and API Keys Logged to Application Output
- **Severity:** High (CVSS 7.5)
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)

### Technical Description
The HTTP logging middleware records all incoming request headers and configuration objects in application logs:
```javascript
app.use((req, res, next) => {
  logger.info('Incoming request headers', { headers: req.headers, env: process.env });
  next();
});
```
This logs `process.env.AWS_SECRET_ACCESS_KEY` and client `Authorization: Bearer <token>` to centralized Elasticsearch/Datadog logs accessible to all internal developers.

### Hardened Implementation
```javascript
const SENSITIVE_KEYS = new Set(['authorization', 'cookie', 'x-api-key']);

app.use((req, res, next) => {
  const sanitizedHeaders = { ...req.headers };
  for (const key of Object.keys(sanitizedHeaders)) {
    if (SENSITIVE_KEYS.has(key.toLowerCase())) sanitizedHeaders[key] = '[REDACTED]';
  }
  logger.info('Incoming request', { path: req.path, method: req.method, headers: sanitizedHeaders });
  next();
});
```
