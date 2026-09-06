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
    expect(status.runtime.enabled).toBe(true);
    expect(status.runtime.state).toBe('SUSPECT');
    expect(status.runtime.behavior_traces).toBeGreaterThan(0);

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

  it('runs a prepared synthetic shell surface under the deception identity', async () => {
    const sessions = await bridge.getEvolveSessions();
    const activeSession = sessions.sessions.find(
      (session: any) => session.session_id !== 'runtime-default' && session.event_refs.length > 0
    );
    expect(activeSession).toBeTruthy();

    const prepared = await bridge.prepareDeception(activeSession.session_id);
    expect(prepared.instance.validated).toBe(true);
    expect(prepared.runtime.services.length).toBeGreaterThan(0);

    const realWorkspace = await bridge.exec(
      'test ! -e /workspace/.evolve-deception && test ! -e /workspace/.evolve && printf CLEAN'
    );
    expect(realWorkspace.exit_code).toBe(0);
    expect(realWorkspace.stdout).toContain('CLEAN');

    const identity = await bridge.execDeception('id -u', activeSession.session_id);
    expect(identity.exit_code).toBe(0);
    expect(identity.output.trim()).toBe('65533');

    const capabilityState = await bridge.execDeception(
      "grep -E '^(CapEff|CapAmb|NoNewPrivs):' /proc/self/status",
      activeSession.session_id
    );
    expect(capabilityState.exit_code).toBe(0);
    expect(capabilityState.output).toMatch(/^CapEff:\s+0+$/m);
    expect(capabilityState.output).toMatch(/^CapAmb:\s+0+$/m);
    expect(capabilityState.output).toMatch(/^NoNewPrivs:\s+1$/m);

    const shadowMountAttempt = await bridge.execDeception(
      'mkdir -p /tmp/sa-mount-src /tmp/sa-mount-dst && mount --bind /tmp/sa-mount-src /tmp/sa-mount-dst',
      activeSession.session_id
    );
    expect(shadowMountAttempt.exit_code).not.toBe(0);

    const shadowUnshareAttempt = await bridge.execDeception(
      'unshare -m true',
      activeSession.session_id
    );
    expect(shadowUnshareAttempt.exit_code).not.toBe(0);

    const surface = await bridge.execDeception(
      'cat /workspace/manifest.json',
      activeSession.session_id
    );
    expect(surface.exit_code).toBe(0);
    expect(surface.output).toContain('"environment": "production"');

    const service = prepared.runtime.services[0];
    if (service.protocol === 'http') {
      const synthetic = await bridge.execDeception(
        `curl -fsS --connect-timeout 2 http://${service.bind_host}:${service.port}/`,
        activeSession.session_id
      );
      expect(synthetic.exit_code).toBe(0);
      expect(synthetic.output).toContain('"environment":"production"');
      expect(synthetic.output).not.toContain('synthetic');
    }

    const management = await bridge.execDeception(
      'curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:9999/health',
      activeSession.session_id
    );
    expect(management.exit_code).not.toBe(0);

    const external = await bridge.execDeception(
      'curl -fsS --connect-timeout 1 --max-time 2 http://1.1.1.1/',
      activeSession.session_id
    );
    expect(external.exit_code).not.toBe(0);

    await bridge.destroyDeception(activeSession.session_id);
  }, 20_000);

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

describeDocker('Evolve automatic containment-to-deception transition', () => {
  let bridge: SandboxBridge;
  let workspace: string;
  const port = 19119;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-evolve-auto-'));
    bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
    await bridge.ensureRuntime();
    await bridge.setScope({ mode: 'local', arm_canaries: true });
    await bridge.setEvolveEnabled(true);
  }, 60_000);

  afterAll(() => {
    try {
      bridge?.getDocker().stop();
    } finally {
      if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  it('moves a canary-triggered session from real execution into the synthetic shell', async () => {
    await bridge.fsWrite('real-marker.txt', 'REAL_WORKSPACE_MARKER');

    const trigger = await bridge.exec(
      'printf "\\n# touched\\n" >> /workspace/.env.decoy; sleep 1'
    );
    expect([0, -1, 137]).toContain(trigger.exit_code);

    let status: any = null;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      status = await bridge.getEvolveStatus();
      if (status.runtime.state === 'DECEIVE') break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    expect(status.runtime.state).toBe('DECEIVE');

    await expect(
      bridge.request('POST', '/execute', {
        command: 'cat /workspace/real-marker.txt',
      })
    ).rejects.toThrow(/temporarily unavailable/i);

    await expect(
      bridge.request('POST', '/execute', {
        command: 'cat /workspace/real-marker.txt',
        evolve_session_id: 'wrong-session',
      })
    ).rejects.toThrow(/temporarily unavailable/i);

    await expect(
      bridge.setScope({ mode: 'local', arm_canaries: false })
    ).rejects.toThrow(/temporarily unavailable/i);

    let interactiveError = '';
    try {
      await bridge.interactiveInput('y', 'main');
    } catch (error: any) {
      interactiveError = error?.message || '';
    }
    expect(interactiveError).toMatch(/temporarily unavailable/i);
    expect(interactiveError).not.toMatch(/evolve|decept|shadow|synthetic|decoy|canary/i);

    const identity = await bridge.exec('id -u');
    expect(identity.exit_code).toBe(0);
    expect(identity.stdout.trim()).toBe('65533');

    const syntheticManifest = await bridge.fsRead('manifest.json');
    expect(syntheticManifest.content).toContain('"environment": "production"');
    await expect(bridge.fsRead('real-marker.txt')).rejects.toThrow();

    await bridge.fsWrite('notes/operator.txt', 'shadow-note');
    const shadowNote = await bridge.exec('cat /workspace/notes/operator.txt');
    expect(shadowNote.exit_code).toBe(0);
    expect(shadowNote.stdout).toContain('shadow-note');

    const initialMap = await bridge.exec('cat /workspace/ops/service-map.json');
    expect(initialMap.exit_code).toBe(0);
    expect(initialMap.stdout).toContain('app.prod.internal');

    const appHop = await bridge.exec(
      'curl -fsS --connect-timeout 2 http://app.prod.internal:18082/'
    );
    expect(appHop.exit_code).toBe(0);

    const expandedMap = await bridge.exec('cat /workspace/ops/service-map.json');
    expect(expandedMap.exit_code).toBe(0);
    expect(expandedMap.stdout).toContain('db-prod.internal');

    const workspaceView = await bridge.exec('pwd; ls -la /workspace; cat /workspace/manifest.json');
    expect(workspaceView.exit_code).toBe(0);
    expect(workspaceView.stdout).toContain('/workspace');
    expect(workspaceView.stdout).toContain('"environment": "production"');

    const management = await bridge.exec(
      'curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:9999/health'
    );
    expect(management.exit_code).not.toBe(0);

    const external = await bridge.exec(
      'curl -fsS --connect-timeout 1 --max-time 2 http://1.1.1.1/'
    );
    expect(external.exit_code).not.toBe(0);
  }, 20_000);
});
