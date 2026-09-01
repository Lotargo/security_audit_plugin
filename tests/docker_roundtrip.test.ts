import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { SandboxBridge } from '../src/mcp/bridge.js';

const enabled = process.env.SECURITY_AUDIT_DOCKER_E2E === '1';
const describeDocker = enabled ? describe : describe.skip;

describeDocker('live Docker host-to-sandbox roundtrip & escape-regression suite', () => {
  let bridge: SandboxBridge;
  let workspace: string;
  let hostProbeServer: http.Server;
  const port = 19099;
  const hostProbePort = 19101;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-docker-e2e-'));

    hostProbeServer = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('HOST_PROBE_OK');
    });
    await new Promise<void>((resolve, reject) => {
      hostProbeServer.once('error', reject);
      hostProbeServer.listen(hostProbePort, '0.0.0.0', () => resolve());
    });

    bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
    await bridge.ensureRuntime();
  }, 60_000);

  afterAll(async () => {
    try {
      bridge?.getDocker().stop();
    } finally {
      if (hostProbeServer) {
        await new Promise<void>((resolve) => hostProbeServer.close(() => resolve()));
      }
      if (workspace) fs.rmSync(workspace, { recursive: true, force: true });
    }
  });

  describe('Control-plane security & authentication boundary', () => {
    it('keeps /health public but rejects unsigned protected requests with 401', async () => {
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

  describe('Pre-scope & Local scope containment (Points 1, 2)', () => {
    it('starts with fail-closed egress before any scope is provisioned (Point 1)', async () => {
      const domainCurl = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 https://example.com >/dev/null'
      );
      expect(domainCurl.exit_code).not.toBe(0);

      const ipCurl = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://93.184.216.34 >/dev/null'
      );
      expect(ipCurl.exit_code).not.toBe(0);

      const publicIpCurl = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://1.1.1.1 >/dev/null'
      );
      expect(publicIpCurl.exit_code).not.toBe(0);
    }, 15_000);

    it('enforces fail-closed isolation in local scope mode (Point 2)', async () => {
      const scope = await bridge.setScope({ mode: 'local', arm_canaries: false });
      expect(scope.status).toBe('success');
      expect(scope.mode).toBe('local');

      const domainCurl = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 https://example.com >/dev/null'
      );
      expect(domainCurl.exit_code).not.toBe(0);

      const ipCurl = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://93.184.216.34 >/dev/null'
      );
      expect(ipCurl.exit_code).not.toBe(0);

      await expect(bridge.httpProbe({ url: 'https://example.com' })).rejects.toThrow(
        'require an explicit remote or hybrid scope'
      );
      await expect(bridge.browserAudit({ url: 'https://example.com' })).rejects.toThrow(
        'require an explicit remote or hybrid scope'
      );
    }, 15_000);
  });

  describe('Process privilege & nftables control containment (Points 3, 4, 5)', () => {
    it('runs agent execution processes under an unprivileged non-root identity (Point 3)', async () => {
      const identity = await bridge.exec('id -u');
      expect(identity.exit_code).toBe(0);
      const uid = Number(identity.stdout.trim());
      expect(uid).toBeGreaterThan(0);
      expect(identity.stdout.trim()).not.toBe('0');

      const whoami = await bridge.exec('whoami');
      expect(whoami.exit_code).toBe(0);
      expect(whoami.stdout.trim()).not.toBe('root');
    });

    it('prevents unprivileged agent processes from reading or altering nftables/iptables (Point 4)', async () => {
      const nftList = await bridge.exec('nft list ruleset');
      expect(nftList.exit_code).not.toBe(0);

      const nftFlush = await bridge.exec('nft flush ruleset');
      expect(nftFlush.exit_code).not.toBe(0);

      const iptList = await bridge.exec('iptables -L -n');
      expect(iptList.exit_code).not.toBe(0);
    });

    it('blocks agent process from directly connecting to Tor SOCKS 9050 and ControlPort 9051 (Point 5)', async () => {
      const torSocks = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 --socks5-hostname 127.0.0.1:9050 http://93.184.216.34 >/dev/null'
      );
      expect(torSocks.exit_code).not.toBe(0);

      const torControl = await bridge.exec(
        'python3 -c "import socket; s = socket.create_connection((\'127.0.0.1\', 9051), timeout=2); s.sendall(b\'AUTHENTICATE\\r\\n\')"'
      );
      expect(torControl.exit_code).not.toBe(0);
    });
  });

  describe('L3 Network Boundary, Scope Pinning & Egress Regression (Points 6, 7, 8, 9, 10)', () => {
    it('allows direct remote scope to connect ONLY to approved in-scope destination and verifies pinned L3 allowlist (Point 6)', async () => {
      const scope = await bridge.setScope({
        mode: 'remote',
        targets: ['93.184.216.34'],
        arm_canaries: false,
      });
      expect(scope.status).toBe('success');
      expect(scope.mode).toBe('remote');
      expect(scope.allowed_cidrs).toEqual(['93.184.216.34/32']);
    });

    it('blocks arbitrary public IPs outside the active remote scope (Point 7)', async () => {
      // With scope locked strictly to 93.184.216.34:
      const blocked1 = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://1.1.1.1/ >/dev/null'
      );
      expect(blocked1.exit_code).not.toBe(0);

      const blocked2 = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://8.8.8.8/ >/dev/null'
      );
      expect(blocked2.exit_code).not.toBe(0);

      await expect(bridge.httpProbe({ url: 'http://1.1.1.1/' })).rejects.toThrow(
        'outside the active audit scope'
      );
    });

    it('blocks RFC1918 and private network destinations during remote audits (Point 8)', async () => {
      const priv10 = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://10.0.0.1/ >/dev/null'
      );
      expect(priv10.exit_code).not.toBe(0);

      const priv192 = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://192.168.1.1/ >/dev/null'
      );
      expect(priv192.exit_code).not.toBe(0);

      const priv172 = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://172.16.0.1/ >/dev/null'
      );
      expect(priv172.exit_code).not.toBe(0);

      await expect(bridge.httpProbe({ url: 'http://10.0.0.1/' })).rejects.toThrow(
        'outside the active audit scope'
      );
    }, 15_000);

    it('blocks cloud metadata endpoint (169.254.169.254) (Point 9)', async () => {
      const meta = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://169.254.169.254/latest/meta-data/ >/dev/null'
      );
      expect(meta.exit_code).not.toBe(0);

      await expect(
        bridge.httpProbe({ url: 'http://169.254.169.254/latest/meta-data/' })
      ).rejects.toThrow();
    });

    it('prevents IPv6 from bypassing IPv4 policy (Point 10)', async () => {
      const v6Public = await bridge.exec(
        'curl -g -6 -fsS --connect-timeout 2 --max-time 3 "http://[2606:4700:4700::1111]/" >/dev/null'
      );
      expect(v6Public.exit_code).not.toBe(0);

      const v6LinkLocal = await bridge.exec(
        'curl -g -6 -fsS --connect-timeout 2 --max-time 3 "http://[fe80::1]/" >/dev/null'
      );
      expect(v6LinkLocal.exit_code).not.toBe(0);

      const v6UniqueLocal = await bridge.exec(
        'curl -g -6 -fsS --connect-timeout 2 --max-time 3 "http://[fc00::1]/" >/dev/null'
      );
      expect(v6UniqueLocal.exit_code).not.toBe(0);
    });
  });

  describe('L7 Browser, Redirects & Tor Containment (Points 11, 12, 13)', () => {
    it('prevents browser from navigating to out-of-scope hostnames (Point 11)', async () => {
      await expect(
        bridge.browserAudit({ url: 'https://attacker.example.com/phish' })
      ).rejects.toThrow('outside the active audit scope');
    });

    it('rejects cross-host redirects in http_probe fail-closed (Point 12)', async () => {
      // Start a lightweight redirect service on container loopback
      await bridge.startBackground(
        `node -e "const http = require('http'); http.createServer((req, res) => { if (req.url === '/redirect-cross') { res.writeHead(302, { Location: 'http://1.1.1.1/stolen' }); res.end(); } else if (req.url === '/redirect-same') { res.writeHead(302, { Location: 'http://127.0.0.1:18080/ok' }); res.end(); } else { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end('OK_LANDED'); } }).listen(18080);"`,
        'ci_redirect_srv'
      );
      await new Promise((resolve) => setTimeout(resolve, 600));

      // Provision scope for the mock endpoint
      await bridge.setScope({
        mode: 'remote',
        targets: ['127.0.0.1'],
        arm_canaries: false,
      });

      // Same-host redirect must be permitted
      const sameHostRes = await bridge.httpProbe({ url: 'http://127.0.0.1:18080/redirect-same' });
      expect(sameHostRes.status).toBe(200);
      expect(sameHostRes.body).toContain('OK_LANDED');

      // Cross-host redirect to an out-of-scope host (1.1.1.1) must fail-closed
      await expect(
        bridge.httpProbe({ url: 'http://127.0.0.1:18080/redirect-cross' })
      ).rejects.toThrow();

      await bridge.request('POST', '/kill_background', { session: 'ci_redirect_srv' });
    });

    it('provisions Tor scopes without normal DNS leakage and enforces agent DNS blocking (Point 13)', async () => {
      const torScope = await bridge.setScope({
        mode: 'remote',
        targets: ['http://expyuz5wqqgahqda.onion'],
        proxy: 'tor',
        arm_canaries: false,
      });
      expect(torScope.status).toBe('success');
      expect(torScope.tor_enabled).toBe(true);
      expect(torScope.allowed_cidrs).toEqual([]);

      // Agent process must be blocked from querying port 53 DNS directly
      const dnsQuery = await bridge.exec(
        'getent hosts example.com 2>/dev/null || nslookup example.com 127.0.0.11 2>/dev/null || curl -fsS --connect-timeout 2 http://93.184.216.34 >/dev/null'
      );
      expect(dnsQuery.exit_code).not.toBe(0);
    }, 15_000);
  });

  describe('Emergency Kill Switch & Hard Reset Lifecycle (Points 14, 15)', () => {
    it('proves killSwitch transitions a previously reachable scoped destination to fail-closed (Point 14)', async () => {
      // Use a deterministic server on the Docker host rather than relying on public Internet
      // availability. The container default gateway is outside loopback, so the kill-switch output
      // policy must actually block this connection after the transition.
      const gatewayResult = await bridge.exec("ip route show default | awk 'NR==1 {print $3}'");
      expect(gatewayResult.exit_code).toBe(0);
      const gateway = gatewayResult.stdout.trim();
      expect(gateway).toMatch(/^\d{1,3}(?:\.\d{1,3}){3}$/);

      const directScope = await bridge.setScope({
        mode: 'remote',
        targets: [gateway],
        denied_cidrs: [],
        arm_canaries: false,
      });
      expect(directScope.status).toBe('success');

      const egressBeforeKill = await bridge.exec(
        `curl -fsS --connect-timeout 2 --max-time 3 http://${gateway}:${hostProbePort}/`
      );
      expect(egressBeforeKill.exit_code).toBe(0);
      expect(egressBeforeKill.stdout).toContain('HOST_PROBE_OK');

      const killResult = await bridge.killSwitch('Adversarial validation test');
      expect(killResult.status).toBe('isolated');
      expect(killResult.is_isolated).toBe(true);

      const egressAfterKill = await bridge.exec(
        `curl -fsS --connect-timeout 2 --max-time 3 http://${gateway}:${hostProbePort}/`
      );
      expect(egressAfterKill.exit_code).not.toBe(0);

      await expect(bridge.httpProbe({ url: `http://${gateway}:${hostProbePort}/` })).rejects.toThrow(
        'require an explicit remote or hybrid scope'
      );
    }, 20_000);

    it('clears previous network scope, Tor state, and egress capability after hard reset (Point 15)', async () => {
      const resetResult = await bridge.reset(true);
      expect(resetResult.status).toBe('ok');

      const isHealthy = await bridge.getDocker().checkHealth();
      expect(isHealthy).toBe(true);

      // Fresh container starts with bootstrap local isolation
      const initialAfterReset = await bridge.exec(
        'curl -fsS --connect-timeout 2 --max-time 3 http://93.184.216.34 >/dev/null'
      );
      expect(initialAfterReset.exit_code).not.toBe(0);

      await expect(bridge.httpProbe({ url: 'http://127.0.0.1:18080/' })).rejects.toThrow(
        'require an explicit remote or hybrid scope'
      );
    }, 30_000);
  });
});
