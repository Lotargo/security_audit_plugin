import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { SandboxBridge } from '../src/mcp/bridge.js';

const enabled = process.env.SECURITY_AUDIT_DOCKER_E2E === '1';
const describeDocker = enabled ? describe : describe.skip;

describeDocker('live Docker host-to-sandbox roundtrip', () => {
  let bridge: SandboxBridge;
  let workspace: string;
  const port = 19099;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-docker-e2e-'));
    bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
    await bridge.ensureRuntime();
  }, 30_000);

  afterAll(() => {
    try {
      bridge?.getDocker().stop();
    } finally {
      if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  it('keeps /health public but rejects unsigned protected requests', async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.get(
        { host: '127.0.0.1', port, path: '/isolation_status', timeout: 2000 },
        (res) => {
          res.resume();
          resolve(res.statusCode || 0);
        }
      );
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('unsigned protected request timed out'));
      });
    });
    expect(status).toBe(401);
  });

  it('runs the protected browser RPC using stdin JSON transport', async () => {
    const report = await bridge.browserAudit({
      url: 'https://example.com',
      bypass_turnstile: false,
      generate_decoy_noise: false,
    });
    expect(report.target_url).toBe('https://example.com');
    expect(typeof report.network_requests_count).toBe('number');
  }, 60_000);

  it('drops agent execution privileges and preserves encrypted command execution', async () => {
    const scope = await bridge.setScope({ mode: 'local', arm_canaries: false });
    expect(scope.status).toBe('success');
    expect(scope.mode).toBe('local');

    const identity = await bridge.exec('id -u');
    expect(identity.exit_code).toBe(0);
    expect(identity.stdout.trim()).not.toBe('0');

    const nftAccess = await bridge.exec('nft list ruleset');
    expect(nftAccess.exit_code).not.toBe(0);

    const result = await bridge.exec('printf CONTROL_PLANE_OK');
    expect(result.exit_code).toBe(0);
    expect(result.stdout).toContain('CONTROL_PLANE_OK');
  }, 30_000);

  it('signs GET path+query identically on host and daemon', async () => {
    await bridge.startBackground('printf QUERY_SIGNING_OK; sleep 1', 'ci_query_signing');
    await new Promise((resolve) => setTimeout(resolve, 250));

    let combined = '';
    for (let i = 0; i < 5; i += 1) {
      const poll = await bridge.pollLogs('ci_query_signing');
      combined += poll.delta_logs || '';
      if (combined.includes('QUERY_SIGNING_OK')) break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    expect(combined).toContain('QUERY_SIGNING_OK');
  });
});
