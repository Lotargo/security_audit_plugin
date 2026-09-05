import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as http from 'node:http';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { SandboxBridge } from '../src/mcp/bridge.js';

describe('SandboxBridge.request error handling', () => {
  let server: http.Server;
  let port: number;
  let workspace: string;
  let handler: (req: http.IncomingMessage, res: http.ServerResponse) => void;
  let requestCount: number;

  beforeAll(async () => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-bridge-req-'));
    requestCount = 0;
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{}');
    };
    server = http.createServer((req, res) => {
      requestCount += 1;
      handler(req, res);
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as net.AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve()))
    );
    fs.rmSync(workspace, { recursive: true, force: true });
  });

  function bridge() {
    return new SandboxBridge({ workspaceRoot: workspace, hostPort: port });
  }

  it('parses a JSON success body', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    };
    await expect(bridge().request('GET', '/health')).resolves.toEqual({ status: 'ok' });
  });

  it('returns a plain-text success body as-is', async () => {
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('KILL_SWITCH_PEER_OK');
    };
    await expect(bridge().request('GET', '/peer')).resolves.toBe('KILL_SWITCH_PEER_OK');
  });

  it('surfaces the daemon error message for JSON error bodies', async () => {
    handler = (_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'boom' }));
    };
    await expect(bridge().request('GET', '/execute')).rejects.toThrow('boom');
  });

  it('reports HTTP status instead of SyntaxError for an empty error body', async () => {
    handler = (_req, res) => {
      res.writeHead(503);
      res.end();
    };
    const err = await bridge().request('GET', '/execute').catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toContain('HTTP 503');
    expect(err.message).not.toMatch(/JSON|Unexpected end/i);
  });

  it('reports HTTP status for a non-JSON error body', async () => {
    handler = (_req, res) => {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end('Bad Gateway');
    };
    const err = await bridge().request('GET', '/execute').catch((e: Error) => e);
    expect(err.message).toContain('HTTP 500');
    expect(err.message).toContain('Bad Gateway');
  });

  it('retries once on 401 and then succeeds', async () => {
    let calls = 0;
    handler = (_req, res) => {
      calls += 1;
      if (calls === 1) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'unauthorized' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok' }));
    };
    await expect(bridge().request('GET', '/execute')).resolves.toEqual({ status: 'ok' });
    expect(calls).toBe(2);
  });

  it('throws after the 401 retry is exhausted', async () => {
    requestCount = 0;
    handler = (_req, res) => {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
    };
    const err = await bridge().request('GET', '/execute').catch((e: Error) => e);
    // Daemon JSON error text wins; the two attempts prove the single retry happened.
    expect(err.message).toBe('unauthorized');
    expect(requestCount).toBe(2);
  });

  it('reports unreachable daemons without masking the cause', async () => {
    const dead = new SandboxBridge({ workspaceRoot: workspace, hostPort: 1 });
    await expect(dead.request('GET', '/health', undefined, 0)).rejects.toThrow(
      /unreachable|timed out/i
    );
  });
});
