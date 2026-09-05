import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SandboxBridge } from '../src/mcp/bridge.js';

const enabled = process.env.SECURITY_AUDIT_DOCKER_E2E === '1';
const describeDocker = enabled ? describe : describe.skip;

describeDocker('Evolve live Docker behavior pipeline', () => {
  let bridge: SandboxBridge;
  let workspace: string;
  const port = 19109;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-evolve-e2e-'));
    bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
    await bridge.ensureRuntime();
    await bridge.setScope({ mode: 'local', arm_canaries: false });
    await bridge.setEvolveEnabled(true);
  }, 60_000);

  afterAll(() => {
    try {
      bridge?.getDocker().stop();
    } finally {
      if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  it('correlates real exec telemetry into a medium-risk behavior trace', async () => {
    const discovery = await bridge.exec('whoami');
    expect(discovery.exit_code).toBe(0);

    // Local mode is intentionally fail-closed for outbound networking. The command itself is still
    // observable, so BehaviorProfiler can correlate discovery -> network intent without allowing
    // the connection to escape the sandbox.
    const network = await bridge.exec(
      'curl -fsS --connect-timeout 1 --max-time 2 https://example.com >/dev/null'
    );
    expect(network.exit_code).not.toBe(0);

    const status = await bridge.getEvolveStatus();
    expect(status.enabled).toBe(true);
    expect(status.state).toBe('SUSPECT');
    expect(status.behavior_traces).toBeGreaterThan(0);

    const sessions = await bridge.getEvolveSessions();
    const activeSession = sessions.sessions.find(
      (session: any) => session.session_id !== 'runtime-default' && session.event_refs.length > 0
    );
    expect(activeSession).toBeTruthy();

    const trace = await bridge.getEvolveTrace(activeSession.session_id);
    expect(trace.risk_level).toBe('MEDIUM');
    expect(trace.risk_score).toBe(45);
    expect(trace.tags).toEqual(
      expect.arrayContaining(['execution', 'discovery', 'network_activity'])
    );
    expect(trace.events.length).toBeGreaterThanOrEqual(4);
    expect(Object.keys(trace.process_lineage).length).toBeGreaterThan(0);
  }, 15_000);

  it('keeps the runtime network boundary intact while Evolve observes behavior', async () => {
    const isolation = await bridge.request<{ is_isolated: boolean }>(
      'GET',
      '/isolation_status'
    );
    expect(isolation.is_isolated).toBe(false);

    const blocked = await bridge.exec(
      'curl -fsS --connect-timeout 1 --max-time 2 http://1.1.1.1 >/dev/null'
    );
    expect(blocked.exit_code).not.toBe(0);
  }, 10_000);
});
