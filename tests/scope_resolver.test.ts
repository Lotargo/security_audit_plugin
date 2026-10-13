import { describe, expect, it } from 'vitest';
import {
  extractTargetHostname,
  isUrlInScope,
  normalizeCidrList,
  normalizeIpSpec,
  normalizeScopeHosts,
  resolveScopeTargets,
} from '../src/mcp/security/scope_resolver.js';

describe('scope resolver', () => {
  it('normalizes IPs and CIDRs without accepting malformed prefixes', () => {
    expect(normalizeIpSpec('93.184.216.34')).toBe('93.184.216.34/32');
    expect(normalizeIpSpec('2001:db8::1')).toBe('2001:db8::1/128');
    expect(normalizeIpSpec('10.0.0.0/8')).toBe('10.0.0.0/8');
    expect(normalizeIpSpec('2001:db8::/32')).toBe('2001:db8::/32');
    expect(normalizeIpSpec('10.0.0.1/33')).toBeNull();
    expect(normalizeIpSpec('2001:db8::1/129')).toBeNull();
  });

  it('extracts hostnames from domains, host:port values and URLs', () => {
    expect(extractTargetHostname('example.com')).toBe('example.com');
    expect(extractTargetHostname('example.com:8443/path')).toBe('example.com');
    expect(extractTargetHostname('https://api.example.com/v1')).toBe('api.example.com');
    expect(extractTargetHostname('[2001:db8::1]:443')).toBe('2001:db8::1');
  });

  it('pins every DNS answer as an explicit host CIDR and deduplicates results', async () => {
    const resolver = async (hostname: string) => {
      expect(hostname).toBe('example.com');
      return ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946', '93.184.216.34'];
    };

    await expect(resolveScopeTargets(['https://example.com/path'], resolver)).resolves.toEqual([
      '2606:2800:220:1:248:1893:25c8:1946/128',
      '93.184.216.34/32',
    ]);
  });

  it('keeps explicit CIDRs without doing DNS resolution', async () => {
    const resolver = async () => {
      throw new Error('resolver must not be called');
    };

    await expect(
      resolveScopeTargets(['203.0.113.10', '198.51.100.0/24', '2001:db8::/32'], resolver)
    ).resolves.toEqual(['198.51.100.0/24', '2001:db8::/32', '203.0.113.10/32']);
  });

  it('fails closed on invalid CIDR configuration or unresolvable targets', async () => {
    expect(() => normalizeCidrList(['10.0.0.1/99'], 'allowed CIDR')).toThrow(
      'Invalid allowed CIDR entry'
    );

    await expect(
      resolveScopeTargets(['missing.example'], async () => {
        throw new Error('ENOTFOUND');
      })
    ).rejects.toThrow('Failed to resolve scope target missing.example');
  });

  it('builds exact L7 host allowlists and rejects broad proxy/Tor CIDRs', () => {
    expect(
      normalizeScopeHosts(['https://Example.COM/path', '203.0.113.7', 'example.com:8443'])
    ).toEqual(['203.0.113.7', 'example.com', 'example.com:8443']);

    expect(() => normalizeScopeHosts(['198.51.100.0/24'])).toThrow(
      'Proxy/Tor scope target must be a single host'
    );
  });

  it('matches managed network calls to exact scoped hosts only', () => {
    const hosts = normalizeScopeHosts(['example.com', 'api.example.com']);
    expect(isUrlInScope('https://example.com/a', hosts)).toBe(true);
    expect(isUrlInScope('https://api.example.com/v1', hosts)).toBe(true);
    expect(isUrlInScope('https://www.example.com/', hosts)).toBe(false);
    expect(isUrlInScope('file:///etc/passwd', hosts)).toBe(false);
  });

  it('enforces explicit ports without expanding host:port to bare host (ROADMAP п.5)', () => {
    const hosts = normalizeScopeHosts(['localhost:18081']);
    expect(hosts).toEqual(['localhost:18081']);
    expect(isUrlInScope('http://localhost:18081/', hosts)).toBe(true);
    expect(isUrlInScope('http://localhost:9999/', hosts)).toBe(false);
    expect(isUrlInScope('http://localhost:9050/', hosts)).toBe(false);
    // Bare host keeps legacy any-port semantics.
    const bare = normalizeScopeHosts(['localhost']);
    expect(isUrlInScope('http://localhost:9999/', bare)).toBe(true);
  });
});
