import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SandboxBridge } from '../src/mcp/bridge.js';

const enabled = process.env.SECURITY_AUDIT_DOCKER_E2E === '1';
const describeDocker = enabled ? describe : describe.skip;

describeDocker('final Docker security hardening regressions', () => {
  let bridge: SandboxBridge;
  let workspace: string;
  const port = 19199;
  const localServerPort = 18081;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-hardening-e2e-'));
    bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
    await bridge.ensureRuntime();

    const serverScript =
      "require('http').createServer((_req,res)=>{res.writeHead(200,{'content-type':'text/plain'});res.end('MANAGED_ONLY_OK');}).listen(18081,'::')";
    execFileSync(
      'docker',
      [
        'exec',
        '-d',
        'security-audit-sandbox',
        '/usr/bin/node',
        '-e',
        serverScript,
      ],
      { stdio: 'ignore' }
    );
    await new Promise((resolve) => setTimeout(resolve, 400));
  }, 60_000);

  afterAll(() => {
    try {
      bridge?.getDocker().stop();
    } finally {
      if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  it('does not expose control-plane trust material to sandbox_exec children', async () => {
    const result = await bridge.exec('env');
    expect(result.exit_code).toBe(0);
    expect(result.stdout).not.toContain('BRIDGE_SESSION_KEY_HEX=');
    expect(result.stdout).not.toContain('HOST_PUBKEY_HEX=');
  });

  it('does not expose control-plane trust material to background tmux panes', async () => {
    await bridge.startBackground('env; sleep 1', 'hardening_clean_env');
    await new Promise((resolve) => setTimeout(resolve, 300));

    let output = '';
    for (let i = 0; i < 5; i += 1) {
      const poll = await bridge.pollLogs('hardening_clean_env');
      output += poll.delta_logs || '';
      if (output.includes('PATH=')) break;
      await new Promise((resolve) => setTimeout(resolve, 150));
    }

    expect(output).toContain('PATH=');
    expect(output).not.toContain('BRIDGE_SESSION_KEY_HEX=');
    expect(output).not.toContain('HOST_PUBKEY_HEX=');
  });

  it('blocks raw agent access to the container DNS service even in remote mode', async () => {
    await bridge.setScope({
      mode: 'remote',
      targets: ['127.0.0.1'],
      denied_cidrs: [],
      arm_canaries: false,
    });

    const dnsTcp = await bridge.exec(
      "python3 -c \"import socket; socket.create_connection(('127.0.0.11',53),timeout=1)\""
    );
    expect(dnsTcp.exit_code).not.toBe(0);
  });

  it('keeps domain-resolved CIDRs managed-only while allowing the managed probe', async () => {
    const scope = await bridge.setScope({
      mode: 'remote',
      targets: ['localhost'],
      denied_cidrs: [],
      arm_canaries: false,
    });
    expect(scope.agent_allowed_cidrs).toEqual([]);
    expect(scope.allowed_cidrs.length).toBeGreaterThan(0);

    const managed = await bridge.httpProbe({ url: `http://localhost:${localServerPort}/` });
    expect(managed.status).toBe(200);
    expect(managed.body).toContain('MANAGED_ONLY_OK');

    const raw = await bridge.exec(
      `curl -fsS --connect-timeout 2 --max-time 3 http://127.0.0.1:${localServerPort}/`
    );
    expect(raw.exit_code).not.toBe(0);
  });

  it('rejects authority overrides at the daemon boundary even when bypassing bridge helpers', async () => {
    await expect(
      bridge.request('POST', '/http_probe', {
        url: `http://localhost:${localServerPort}/`,
        method: 'GET',
        headers: { Host: 'evil.example' },
        body: '',
        proxy: null,
        allowed_hosts: ['localhost'],
      })
    ).rejects.toThrow(/Host\/:authority/i);

    await expect(
      bridge.request('POST', '/browser_audit', {
        url: `http://localhost:${localServerPort}/`,
        proxy: null,
        allowed_hosts: ['localhost'],
        spoof_headers: { Host: 'evil.example' },
      })
    ).rejects.toThrow(/Host\/:authority/i);
  });

  it('rejects managed daemon requests without an explicit L7 host scope', async () => {
    await expect(
      bridge.request('POST', '/http_probe', {
        url: `http://localhost:${localServerPort}/`,
        method: 'GET',
        headers: {},
        body: '',
        proxy: null,
        allowed_hosts: [],
      })
    ).rejects.toThrow(/explicit RoE host allowlist/i);

    await expect(
      bridge.request('POST', '/browser_audit', {
        url: `http://localhost:${localServerPort}/`,
        proxy: null,
        allowed_hosts: [],
      })
    ).rejects.toThrow(/explicit RoE host allowlist/i);
  });
});
