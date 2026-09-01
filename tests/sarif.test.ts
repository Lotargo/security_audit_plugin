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

  it('correctly builds fixes, remediation guide, and attack graph visualizations', () => {
    const builder = new SarifReportBuilder();
    builder.addFinding({
      ruleId: 'SEC-RCE-001',
      ruleName: 'Remote Code Execution via Command Injection',
      level: 'error',
      message: 'Unsanitized input passed to child_process.exec()',
      filePath: 'src/utils/backup.ts',
      startLine: 20,
      endLine: 20,
      snippet: 'exec(`tar -czf ${req.body.filename} /data`);',
      cvssScore: 9.8,
      cwe: ['CWE-78'],
      remediationMarkdown: 'Replace `child_process.exec` with `execFile` or `spawn` using an array of arguments.',
      fixes: [
        {
          description: 'Use execFile with argument array instead of shell concatenation',
          file: 'src/utils/backup.ts',
          startLine: 20,
          endLine: 20,
          replacement: 'execFile("tar", ["-czf", req.body.filename, "/data"]);',
        },
      ],
      attackGraph: {
        nodes: [
          { id: 'Attacker', label: 'External Attacker' },
          { id: 'API', label: 'POST /api/backup Endpoint' },
          { id: 'Shell', label: 'Linux Shell / Subprocess' },
          { id: 'Host', label: 'Underlying Host Infrastructure' },
        ],
        edges: [
          { from: 'Attacker', to: 'API', label: 'malicious payload in filename' },
          { from: 'API', to: 'Shell', label: 'command concatenation' },
          { from: 'Shell', to: 'Host', label: 'arbitrary code execution' },
        ],
      },
    });

    const sarif = builder.build();
    const result = sarif.runs[0].results[0];
    expect(result.fixes).toBeDefined();
    expect(result.fixes?.[0].description.text).toContain('execFile');
    expect(result.fixes?.[0].changes?.[0].replacements[0].insertedContent?.text).toContain('execFile("tar"');

    const md = builder.exportMarkdownSummary();
    expect(md).toContain('**Attack Vector & Blast Radius Graph**:');
    expect(md).toContain('flowchart LR');
    expect(md).toContain('Attacker["External Attacker"]');
    expect(md).toContain('**Suggested Fix**:');
    expect(md).toContain('execFile("tar"');
    expect(md).toContain('**Remediation Guide**:');
  });
});
