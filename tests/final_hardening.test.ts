import { describe, expect, it, vi } from 'vitest';
import { SandboxBridge } from '../src/mcp/bridge.js';
import { normalizeAgentNetworkTargets } from '../src/mcp/security/scope_resolver.js';

describe('final RoE hardening invariants', () => {
  it('grants raw agent egress only to explicit IP/CIDR targets, never domain targets', () => {
    expect(
      normalizeAgentNetworkTargets([
        'example.com',
        'https://203.0.113.7/path',
        '198.51.100.0/24',
        '[2001:db8::7]',
      ])
    ).toEqual([
      '198.51.100.0/24',
      '2001:db8::7/128',
      '203.0.113.7/32',
    ]);
  });

  it('marks domain-resolved CIDRs managed-only in the provisioning payload', async () => {
    const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19996 });
    const requestSpy = vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

    await bridge.setScope({
      mode: 'remote',
      targets: ['localhost'],
      denied_cidrs: [],
      arm_canaries: false,
    });

    expect(requestSpy).toHaveBeenCalledWith(
      'POST',
      '/provision_egress',
      expect.objectContaining({
        allowed_cidrs: expect.arrayContaining([expect.stringMatching(/\/(32|128)$/)]),
        agent_allowed_cidrs: [],
      })
    );
  });

  it('preserves raw access for explicit single-IP targets', async () => {
    const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19996 });
    const requestSpy = vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

    await bridge.setScope({
      mode: 'remote',
      targets: ['203.0.113.7'],
      arm_canaries: false,
    });

    expect(requestSpy).toHaveBeenCalledWith(
      'POST',
      '/provision_egress',
      expect.objectContaining({
        allowed_cidrs: ['203.0.113.7/32'],
        agent_allowed_cidrs: ['203.0.113.7/32'],
      })
    );
  });

  it('does not allow managed L7 calls from an L3-only CIDR scope', async () => {
    const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19996 });
    vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

    await bridge.setScope({
      mode: 'remote',
      allowed_cidrs: ['203.0.113.7/32'],
      arm_canaries: false,
    });

    await expect(bridge.httpProbe({ url: 'https://example.com' })).rejects.toThrow(
      'require at least one explicit target hostname or single-IP target'
    );
    await expect(bridge.browserAudit({ url: 'https://example.com' })).rejects.toThrow(
      'require at least one explicit target hostname or single-IP target'
    );
  });

  it('rejects Host and :authority overrides before managed requests leave the host bridge', async () => {
    const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19996 });
    vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

    await bridge.setScope({
      mode: 'remote',
      targets: ['203.0.113.7'],
      arm_canaries: false,
    });

    await expect(
      bridge.httpProbe({
        url: 'http://203.0.113.7/',
        headers: { Host: 'evil.example' },
      })
    ).rejects.toThrow('Host/:authority');

    await expect(
      bridge.browserAudit({
        url: 'http://203.0.113.7/',
        spoof_headers: { ':authority': 'evil.example' },
      })
    ).rejects.toThrow('Host/:authority');
  });
});
