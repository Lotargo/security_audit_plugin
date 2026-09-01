# SARIF v2.1.0 Format Specification & Integration

The Security Audit Plugin outputs standard OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format) JSON files.

## Structure Overview

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Security Audit Plugin",
          "semanticVersion": "1.0.0",
          "informationUri": "https://github.com/Lotargo/security_audit_plugin",
          "rules": [
            {
              "id": "SEC001",
              "name": "SQLInjection",
              "shortDescription": { "text": "SQL injection vulnerability detected" },
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "tags": ["security", "CWE-89", "OWASP-A03"],
                "cvssV3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvssScore": 9.8
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SEC001",
          "message": { "text": "Unsanitized user input in query parameter 'id' concatenated into raw SQL string." },
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/controllers/userController.ts" },
                "region": { "startLine": 45, "endLine": 48 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Level Mappings

| Severity | SARIF Level | CVSS Score Range |
| :--- | :--- | :--- |
| Critical | `error` | 9.0 – 10.0 |
| High | `error` | 7.0 – 8.9 |
| Medium | `warning` | 4.0 – 6.9 |
| Low | `note` | 0.1 – 3.9 |
| Informational | `none` | 0.0 |
