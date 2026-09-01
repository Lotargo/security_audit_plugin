import { describe, it, expect } from 'vitest';
import { SarifReportBuilder } from '../src/sarif/builder.js';

describe('SarifReportBuilder OASIS SARIF v2.1.0 Generator', () => {
  it('generates a compliant SARIF log with rules and findings', () => {
    const builder = new SarifReportBuilder();

    builder.addFinding({
      ruleId: 'SEC-SQLI-001',
      ruleName: 'SQL Injection in User Search Parameter',
      level: 'error',
      message: 'Unsanitized user input directly concatenated into SQL query string.',
      filePath: 'src/controllers/userController.ts',
      startLine: 42,
      startColumn: 10,
      endLine: 42,
      endColumn: 55,
      snippet: 'const query = `SELECT * FROM users WHERE name = "${req.query.name}"`;',
      cvssScore: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cwe: ['CWE-89'],
      owasp: ['A03:2021-Injection'],
      mitre: ['T1190'],
      remediation: 'Use parameterized queries or prepared statements.',
    });

    builder.addFinding({
      ruleId: 'SEC-HEADER-002',
      ruleName: 'Missing Content-Security-Policy (CSP) Header',
      level: 'warning',
      message: 'The HTTP response is missing a Content-Security-Policy header.',
      endpointUri: 'https://app.target.local/api/dashboard',
      cvssScore: 5.3,
      cwe: ['CWE-693'],
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation: 'Configure a strict Content-Security-Policy header.',
    });

    const sarif = builder.build();

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('security-audit-plugin');
    expect(run.tool.driver.rules).toHaveLength(2);
    expect(run.results).toHaveLength(2);

    const sqliResult = run.results.find((r) => r.ruleId === 'SEC-SQLI-001');
    expect(sqliResult).toBeDefined();
    expect(sqliResult?.level).toBe('error');
    expect(sqliResult?.locations?.[0]?.physicalLocation?.region?.startLine).toBe(42);
    expect(sqliResult?.locations?.[0]?.physicalLocation?.region?.snippet?.text).toContain('SELECT * FROM users');
    expect(sqliResult?.properties?.cvssScore).toBe(9.8);
  });

  it('generates a Markdown summary report', () => {
    const builder = new SarifReportBuilder();
    builder.addFinding({
      ruleId: 'SEC-XSS-001',
      ruleName: 'Stored Cross-Site Scripting (XSS)',
      level: 'error',
      message: 'Unescaped user input rendered in HTML context.',
      filePath: 'src/views/profile.ejs',
      startLine: 15,
      cvssScore: 8.2,
      cwe: ['CWE-79'],
      remediation: 'Use context-aware HTML entity encoding.',
    });

    const md = builder.exportMarkdownSummary();
    expect(md).toContain('# Security Audit Report');
    expect(md).toContain('🔴 Critical / High (`error`) | 1');
    expect(md).toContain('[SEC-XSS-001] Stored Cross-Site Scripting (XSS)');
    expect(md).toContain('CVSS v3.1: **8.2**');
    expect(md).toContain('CWE-79');
  });
});
