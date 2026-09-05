import { describe, expect, it, vi } from 'vitest';
import { SandboxBridge } from '../src/mcp/bridge.js';

function mockedBridge() {
  const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19997 });
  const request = vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });
  return { bridge, request };
}

function bodyFor(
  request: any,
  path: string
): Record<string, unknown> {
  const call = request.mock.calls.find((entry) => entry[1] === path);
  if (!call) throw new Error(`Expected request to ${path}`);
  return (call[2] || {}) as Record<string, unknown>;
}

describe('SandboxBridge Evolve correlation', () => {
  it('propagates one behavioral session across a scoped audit surface', async () => {
    const { bridge, request } = mockedBridge();

    await bridge.setScope({
      mode: 'remote',
      targets: ['203.0.113.7'],
      arm_canaries: true,
    });

    const provisionBody = bodyFor(request, '/provision_egress');
    expect(typeof provisionBody.evolve_session_id).toBe('string');

    const canaryBody = bodyFor(request, '/arm_canary');
    const sessionId = canaryBody.evolve_session_id;
    expect(typeof sessionId).toBe('string');
    expect(canaryBody).toEqual(
      expect.objectContaining({
        base_dir: '/workspace',
        evolve_session_id: sessionId,
      })
    );
    expect(canaryBody).not.toHaveProperty('token_label');

    request.mockClear();

    await bridge.exec('whoami');
    await bridge.startBackground('printf TEST', 'evolve_bg');
    await bridge.browserAudit({ url: 'https://203.0.113.7/path' });
    await bridge.httpProbe({ url: 'https://203.0.113.7/api' });
    await bridge.interactiveInput('y', 'evolve_tmux');
    await bridge.pollLogs('evolve_bg');

    expect(bodyFor(request, '/execute').evolve_session_id).toBe(sessionId);
    expect(bodyFor(request, '/start_background').evolve_session_id).toBe(sessionId);
    expect(bodyFor(request, '/browser_audit').evolve_session_id).toBe(sessionId);
    expect(bodyFor(request, '/http_probe').evolve_session_id).toBe(sessionId);
    expect(bodyFor(request, '/execute_tmux').evolve_session_id).toBe(sessionId);
    expect(request).toHaveBeenCalledWith(
      'GET',
      `/poll_logs?session=evolve_bg&evolve_session_id=${encodeURIComponent(String(sessionId))}`
    );
  });

  it('rotates the behavioral session when a new scope is provisioned', async () => {
    const { bridge, request } = mockedBridge();

    await bridge.setScope({ mode: 'local', arm_canaries: true });
    const firstSession = bodyFor(request, '/arm_canary').evolve_session_id;

    request.mockClear();
    await bridge.setScope({ mode: 'local', arm_canaries: true });
    const secondSession = bodyFor(request, '/arm_canary').evolve_session_id;

    expect(secondSession).not.toBe(firstSession);
  });

  it('binds Tor mutations to the active behavioral session', async () => {
    const { bridge, request } = mockedBridge();

    await bridge.setScope({
      mode: 'remote',
      targets: ['example.onion'],
      proxy: 'tor',
      arm_canaries: true,
    });
    const sessionId = bodyFor(request, '/arm_canary').evolve_session_id;

    request.mockClear();
    await bridge.rotateTor();

    expect(request).toHaveBeenCalledWith('POST', '/rotate_tor', {
      evolve_session_id: sessionId,
    });
  });

  it('refuses agent reset while a protected runtime state is active', async () => {
    const { bridge } = mockedBridge();
    vi.spyOn(bridge, 'getEvolveStatus').mockResolvedValue({ runtime: { state: 'DECEIVE' } });
    const hardReset = vi.spyOn(bridge.getDocker(), 'hardReset');

    await expect(bridge.reset(true)).rejects.toThrow('temporarily unavailable');
    expect(hardReset).not.toHaveBeenCalled();
  });

  it('exposes authenticated host helpers for Evolve observability', async () => {
    const { bridge, request } = mockedBridge();

    await bridge.setEvolveEnabled(true);
    await bridge.getEvolveStatus();
    await bridge.getEvolveEvents(5000);
    await bridge.getEvolveSessions();
    await bridge.getEvolveTrace('session/test');
    await bridge.prepareDeception('session/test');
    await bridge.getDeceptionStatus('session/test');
    await bridge.execDeception('whoami', 'session/test', 10);
    await bridge.destroyDeception('session/test');

    expect(request).toHaveBeenCalledWith('POST', '/evolve/enable', { enabled: true });
    expect(request).toHaveBeenCalledWith('GET', '/evolve/status');
    expect(request).toHaveBeenCalledWith('GET', '/evolve/events?limit=1000');
    expect(request).toHaveBeenCalledWith('GET', '/evolve/sessions');
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/evolve/trace?session_id=session%2Ftest'
    );
    expect(request).toHaveBeenCalledWith('POST', '/evolve/deception/prepare', {
      session_id: 'session/test',
    });
    expect(request).toHaveBeenCalledWith(
      'GET',
      '/evolve/deception/status?session_id=session%2Ftest'
    );
    expect(request).toHaveBeenCalledWith('POST', '/evolve/deception/exec', {
      session_id: 'session/test',
      command: 'whoami',
      timeout_secs: 10,
    });
    expect(request).toHaveBeenCalledWith('POST', '/evolve/deception/destroy', {
      session_id: 'session/test',
    });
  });
});
