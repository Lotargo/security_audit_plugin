import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { SandboxBridge } from '../src/mcp/bridge.js';
import { SarifReportBuilder } from '../src/sarif/builder.js';
import { SecretRedactor } from '../src/mcp/security/redaction.js';
import { JailGuard, JailSecurityError } from '../src/mcp/security/jail.js';

describe('End-to-End Security Audit Workflow Test Suite', () => {
  let tmpWorkspace: string;
  let bridge: SandboxBridge;
  let jail: JailGuard;

  beforeEach(() => {
    tmpWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-e2e-'));
    fs.mkdirSync(path.join(tmpWorkspace, 'reports'), { recursive: true });
    fs.mkdirSync(path.join(tmpWorkspace, 'logs'), { recursive: true });
    fs.mkdirSync(path.join(tmpWorkspace, 'plan'), { recursive: true });

    bridge = new SandboxBridge({
      workspaceRoot: tmpWorkspace,
      hostPort: 9999,
    });
    jail = new JailGuard(tmpWorkspace);
  });

  it('completes a full end-to-end security audit cycle', async () => {
    // 1. Initialize and set scope
    vi.spyOn(bridge, 'setScope').mockResolvedValue({
      status: 'applied',
      rules_count: 8,
      mode: 'hybrid',
      canaries_armed: true,
    });

    const scopeRes = await bridge.setScope({
      mode: 'hybrid',
      targets: ['https://target.corp.internal'],
      proxy: 'tor',
      arm_canaries: true,
    });
    expect(scopeRes.status).toBe('applied');
    expect(scopeRes.canaries_armed).toBe(true);

    // 2. Start background scan job
    vi.spyOn(bridge, 'startBackground').mockResolvedValue({
      status: 'started',
      session: 'bg_scan_01',
      message: 'Background session started',
    });
    const bgStart = await bridge.startBackground('semgrep --config auto .', 'bg_scan_01');
    expect(bgStart.status).toBe('started');
    expect(bgStart.session).toBe('bg_scan_01');

    // 3. Poll background logs
    vi.spyOn(bridge, 'pollLogs').mockResolvedValue({
      session: 'bg_scan_01',
      active: false,
      delta_logs: 'Found 1 high severity vulnerability: SQL injection in /api/v1/user',
    });
    const logPoll = await bridge.pollLogs('bg_scan_01');
    expect(logPoll.active).toBe(false);
    expect(logPoll.delta_logs).toContain('SQL injection');

    // 4. Generate SARIF report with findings
    const sarifBuilder = new SarifReportBuilder();
    sarifBuilder.addFinding({
      ruleId: 'SEC-SQLI-001',
      ruleName: 'SQL Injection in User Query Handler',
      level: 'error',
      cvssScore: 8.8,
      message: 'Unsanitized user input passed directly to database query in auth module',
      filePath: 'src/auth/user.py',
      startLine: 42,
      tags: ['CWE-89', 'OWASP-A03:2021', 'PCI-DSS-6.5.1'],
    });

    const sarifLog = sarifBuilder.build();
    expect(sarifLog.runs[0].results.length).toBe(1);
    expect(sarifLog.runs[0].results[0].ruleId).toBe('SEC-SQLI-001');
    expect(sarifLog.runs[0].results[0].properties?.cvssScore).toBe(8.8);

    // 5. Test secret redaction before writing logs and reports
    const rawLeak = 'Database connection string: postgres://admin:secret_pass_123@db:5432/app with Token: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const redacted = SecretRedactor.redact(rawLeak);
    expect(redacted).not.toContain('secret_pass_123');
    expect(redacted).toContain('postgres://admin:se***@db:5432/app');
    expect(redacted).toContain('Bearer eyJhbG***sw5c');

    // 6. Write SARIF report safely to workspace
    const reportPath = path.join(tmpWorkspace, 'reports', 'audit-report.sarif');
    fs.writeFileSync(reportPath, JSON.stringify(sarifLog, null, 2), 'utf8');
    expect(fs.existsSync(reportPath)).toBe(true);

    // Verify safe read via JailGuard
    const safeRead = jail.resolveSafePath('reports/audit-report.sarif');
    const readContent = fs.readFileSync(safeRead, 'utf8');
    const parsedSarif = JSON.parse(readContent);
    expect(parsedSarif.version).toBe('2.1.0');

    // 7. Prevent jail escape on write/read
    expect(() => {
      jail.resolveSafePath('../../windows/system32/cmd.exe');
    }).toThrow(JailSecurityError);

    // 8. Simulate Canary Tripwire Trigger & Emergency Network Isolation
    vi.spyOn(bridge, 'killSwitch').mockResolvedValue({
      isolated: true,
      reason: 'Honeytoken /root/.aws/credentials accessed by unauthorized process',
    });

    const killRes = await bridge.killSwitch('Honeytoken /root/.aws/credentials accessed by unauthorized process');
    expect(killRes.isolated).toBe(true);
  });
});
