import { describe, expect, it, vi } from 'vitest';
import { SandboxBridge } from '../src/mcp/bridge.js';

function mockedBridge() {
  const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19998 });
  const request = vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });
  return { bridge, request };
}

describe('SandboxBridge managed network scope', () => {
  it('rejects browser and probe calls before a remote/hybrid scope exists', async () => {
    const { bridge, request } = mockedBridge();

    await expect(bridge.browserAudit({ url: 'https://203.0.113.7' })).rejects.toThrow(
      'require an explicit remote or hybrid scope'
    );
    await expect(bridge.httpProbe({ url: 'https://203.0.113.7' })).rejects.toThrow(
      'require an explicit remote or hybrid scope'
    );
    expect(request).not.toHaveBeenCalled();
  });

  it('enforces exact target hosts on managed network calls', async () => {
    const { bridge, request } = mockedBridge();
    await bridge.setScope({ mode: 'remote', targets: ['203.0.113.7'], arm_canaries: false });
    request.mockClear();

    await expect(bridge.browserAudit({ url: 'https://198.51.100.8' })).rejects.toThrow(
      'outside the active audit scope'
    );
    expect(request).not.toHaveBeenCalled();

    await bridge.browserAudit({ url: 'https://203.0.113.7/path' });
    expect(request).toHaveBeenCalledWith(
      'POST',
      '/browser_audit',
      expect.objectContaining({
        proxy: null,
        allowed_hosts: ['203.0.113.7'],
      })
    );
  });

  it('requires host-level targets for Tor and pins the managed proxy to the active scope', async () => {
    const { bridge, request } = mockedBridge();

    await expect(
      bridge.setScope({ mode: 'remote', allowed_cidrs: ['203.0.113.0/24'], proxy: 'tor' })
    ).rejects.toThrow('Tor scope requires at least one explicit domain, URL, or single-IP target');

    await bridge.setScope({
      mode: 'remote',
      targets: ['203.0.113.7'],
      proxy: 'tor',
      arm_canaries: false,
    });
    expect(request).toHaveBeenCalledWith(
      'POST',
      '/provision_egress',
      expect.objectContaining({
        tor_enabled: true,
        allowed_cidrs: [],
      })
    );
    request.mockClear();

    await bridge.httpProbe({ url: 'https://203.0.113.7' });
    expect(request).toHaveBeenCalledWith(
      'POST',
      '/http_probe',
      expect.objectContaining({
        proxy: 'socks5h://127.0.0.1:9050',
        allowed_hosts: ['203.0.113.7'],
      })
    );

    request.mockClear();
    await bridge.browserAudit({ url: 'https://203.0.113.7', proxy: 'tor' });
    expect(request).toHaveBeenCalledWith(
      'POST',
      '/browser_audit',
      expect.objectContaining({
        proxy: 'socks5://127.0.0.1:9050',
        allowed_hosts: ['203.0.113.7'],
      })
    );

    await expect(
      bridge.httpProbe({ url: 'https://203.0.113.7', proxy: 'http://proxy.invalid:8080' })
    ).rejects.toThrow('Per-call proxy does not match the active sandbox scope');
  });

  it('does not resolve Tor hostnames on the trusted host and preserves onion targets', async () => {
    const { bridge, request } = mockedBridge();

    await bridge.setScope({
      mode: 'remote',
      targets: ['http://examplehiddenservice.onion/'],
      proxy: 'tor',
      arm_canaries: false,
    });

    expect(request).toHaveBeenCalledWith(
      'POST',
      '/provision_egress',
      expect.objectContaining({
        targets: ['http://examplehiddenservice.onion/'],
        allowed_cidrs: [],
        tor_enabled: true,
      })
    );
  });

  it('rejects direct CIDR egress in Tor scopes', async () => {
    const { bridge, request } = mockedBridge();

    await expect(
      bridge.setScope({
        mode: 'remote',
        targets: ['example.com'],
        allowed_cidrs: ['203.0.113.0/24'],
        proxy: 'tor',
      })
    ).rejects.toThrow('Tor scope cannot include allowed_cidrs');
    expect(request).not.toHaveBeenCalled();
  });

  it('fails closed instead of exposing an uncontained external upstream proxy', async () => {
    const { bridge, request } = mockedBridge();

    await expect(
      bridge.setScope({
        mode: 'remote',
        targets: ['203.0.113.7'],
        proxy: 'http://198.51.100.9:8080',
      })
    ).rejects.toThrow('External upstream proxy containment is not implemented safely yet');
    expect(request).not.toHaveBeenCalled();
  });
});
