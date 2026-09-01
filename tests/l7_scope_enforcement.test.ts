import { describe, expect, it, vi } from 'vitest';
import {
  classifyUrl,
  normalizeAllowedHosts,
  normalizeHost,
  isPrivateOrRestrictedIp,
} from '../sandbox_runtime/stealth/browser_guard.js';
import {
  extractTargetHostname,
  isUrlInScope,
  normalizeScopeHosts,
  resolveScopeTargets,
} from '../src/mcp/security/scope_resolver.js';
import { SandboxBridge } from '../src/mcp/bridge.js';

describe('L7 Scope Enforcement & DNS Isolation Test Suite', () => {
  const mockPublicResolver = async (host: string) => {
    return [{ address: '93.184.216.34', family: 4 }];
  };

  describe('Browser URL classification & RoE guard', () => {
    it('allows valid in-scope HTTP/HTTPS targets', async () => {
      const allowedHosts = normalizeAllowedHosts(['example.com', 'api.example.com']);

      const res1 = await classifyUrl(
        'https://example.com/path?query=1',
        false,
        allowedHosts,
        false,
        mockPublicResolver
      );
      expect(res1.ok).toBe(true);

      const res2 = await classifyUrl(
        'http://api.example.com/v1/auth',
        false,
        allowedHosts,
        false,
        mockPublicResolver
      );
      expect(res2.ok).toBe(true);
    });

    it('blocks out-of-scope hostnames even if they are sibling subdomains', async () => {
      const allowedHosts = normalizeAllowedHosts(['example.com']);

      const outOfScope1 = await classifyUrl('https://attacker.com/evil', false, allowedHosts);
      expect(outOfScope1.ok).toBe(false);
      expect(outOfScope1.reason).toContain('outside active RoE scope');

      // example.com must not automatically allow sub.example.com
      const siblingSub = await classifyUrl('https://sub.example.com/path', false, allowedHosts);
      expect(siblingSub.ok).toBe(false);
      expect(siblingSub.reason).toContain('outside active RoE scope: sub.example.com');
    });

    it('denies unsupported protocols fail-closed', async () => {
      const allowedHosts = normalizeAllowedHosts(['example.com']);

      const fileProto = await classifyUrl('file:///etc/passwd', false, allowedHosts);
      expect(fileProto.ok).toBe(false);
      expect(fileProto.reason).toContain('Unsupported protocol: file:');

      const gopherProto = await classifyUrl('gopher://example.com/', false, allowedHosts);
      expect(gopherProto.ok).toBe(false);
      expect(gopherProto.reason).toContain('Unsupported protocol: gopher:');

      const jsProto = await classifyUrl('javascript:alert(1)', false, allowedHosts);
      expect(jsProto.ok).toBe(false);
    });

    it('blocks direct private IP literals unless allowPrivate is set', async () => {
      const allowedHosts = normalizeAllowedHosts(['127.0.0.1', '10.0.0.5', '169.254.169.254']);

      const localhostCheck = await classifyUrl('http://127.0.0.1:8080', false, allowedHosts);
      expect(localhostCheck.ok).toBe(false);
      expect(localhostCheck.reason).toContain('Direct private IP access blocked');

      const metaCheck = await classifyUrl('http://169.254.169.254/latest/meta-data', false, allowedHosts);
      expect(metaCheck.ok).toBe(false);
      expect(metaCheck.reason).toContain('Direct private IP access blocked');

      const rfc1918Check = await classifyUrl('http://10.0.0.5/', false, allowedHosts);
      expect(rfc1918Check.ok).toBe(false);

      const privateAllowed = await classifyUrl('http://127.0.0.1:8080', true, allowedHosts);
      expect(privateAllowed.ok).toBe(true);
    });

    it('blocks public hostnames resolving to private IP addresses (SSRF protection)', async () => {
      const allowedHosts = normalizeAllowedHosts(['internal-spoof.example']);
      const privateResolvingMock = async () => [{ address: '10.0.0.1', family: 4 }];

      const check = await classifyUrl(
        'https://internal-spoof.example/admin',
        false,
        allowedHosts,
        false,
        privateResolvingMock
      );
      expect(check.ok).toBe(false);
      expect(check.reason).toContain('DNS resolves to restricted private IP');
    });

    it('identifies private and restricted IPv4 and IPv6 addresses accurately', () => {
      expect(isPrivateOrRestrictedIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrRestrictedIp('10.200.1.5')).toBe(true);
      expect(isPrivateOrRestrictedIp('172.16.5.10')).toBe(true);
      expect(isPrivateOrRestrictedIp('172.31.255.255')).toBe(true);
      expect(isPrivateOrRestrictedIp('172.32.0.1')).toBe(false);
      expect(isPrivateOrRestrictedIp('192.168.1.1')).toBe(true);
      expect(isPrivateOrRestrictedIp('169.254.169.254')).toBe(true);
      expect(isPrivateOrRestrictedIp('100.64.0.1')).toBe(true);
      expect(isPrivateOrRestrictedIp('::1')).toBe(true);
      expect(isPrivateOrRestrictedIp('fe80::1')).toBe(true);
      expect(isPrivateOrRestrictedIp('fc00::1')).toBe(true);
      expect(isPrivateOrRestrictedIp('93.184.216.34')).toBe(false);
    });
  });

  describe('Tor transport DNS-leak prevention', () => {
    it('bypasses local host-side DNS resolution when isTor is true', async () => {
      const allowedHosts = normalizeAllowedHosts(['unresolvable-target.internal']);
      const failingMockResolver = async () => {
        throw new Error('ENOTFOUND');
      };

      // Without Tor: unresolvable host triggers resolver error
      const directCheck = await classifyUrl(
        'https://unresolvable-target.internal/test',
        false,
        allowedHosts,
        false,
        failingMockResolver
      );
      expect(directCheck.ok).toBe(false);
      expect(directCheck.reason).toContain('DNS resolution failed');

      // With Tor: host resolution is delegated to Tor SOCKS proxy; local DNS is never queried
      const torCheck = await classifyUrl(
        'https://unresolvable-target.internal/test',
        false,
        allowedHosts,
        true,
        failingMockResolver
      );
      expect(torCheck.ok).toBe(true);
      expect(torCheck.reason).toBe('tor_hostname');
    });

    it('permits .onion domains in Tor mode without DNS lookup', async () => {
      const onionHost = 'expyuz5wqqgahqda.onion';
      const allowedHosts = normalizeAllowedHosts([onionHost]);

      const check = await classifyUrl(`http://${onionHost}/index.html`, false, allowedHosts, true);
      expect(check.ok).toBe(true);
      expect(check.reason).toBe('tor_hostname');
    });

    it('rejects out-of-scope .onion destinations even with Tor active', async () => {
      const allowedHosts = normalizeAllowedHosts(['authorized.onion']);

      const check = await classifyUrl('http://unauthorized.onion/', false, allowedHosts, true);
      expect(check.ok).toBe(false);
      expect(check.reason).toContain('outside active RoE scope: unauthorized.onion');
    });
  });

  describe('Scope resolver .onion & Tor handling', () => {
    it('resolves .onion targets without invoking system DNS resolver', async () => {
      const resolverMock = vi.fn().mockRejectedValue(new Error('System DNS should not be called'));

      const targets = ['http://target1.onion', 'https://target2.onion/path'];
      const resolved = await resolveScopeTargets(targets, resolverMock);

      expect(resolved).toEqual([]);
      expect(resolverMock).not.toHaveBeenCalled();
    });

    it('extracts normalized hostnames from .onion URLs and targets', () => {
      const hosts = normalizeScopeHosts([
        'http://expyuz5wqqgahqda.onion/test',
        'SECURE.ONION',
        'https://api.example.com',
      ]);

      expect(hosts).toEqual(['api.example.com', 'expyuz5wqqgahqda.onion', 'secure.onion']);
    });
  });

  describe('Bridge managed network calls RoE pinning', () => {
    it('sets Tor scope with .onion target without performing host DNS resolution', async () => {
      const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19997 });
      const requestSpy = vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

      const res = await bridge.setScope({
        mode: 'remote',
        targets: ['http://my-target.onion'],
        proxy: 'tor',
        arm_canaries: false,
      });

      expect(res.status).toBe('success');
      expect(requestSpy).toHaveBeenCalledWith(
        'POST',
        '/provision_egress',
        expect.objectContaining({
          mode: 'remote',
          tor_enabled: true,
          allowed_cidrs: [],
          targets: ['http://my-target.onion'],
        })
      );

      // Verify browserAudit forwards exact onion allowed_hosts
      await bridge.browserAudit({ url: 'http://my-target.onion/home' });
      expect(requestSpy).toHaveBeenCalledWith(
        'POST',
        '/browser_audit',
        expect.objectContaining({
          proxy: 'socks5://127.0.0.1:9050',
          allowed_hosts: ['my-target.onion'],
        })
      );
    });

    it('rejects cross-host browser audits when URL is outside the active scope', async () => {
      const bridge = new SandboxBridge({ workspaceRoot: process.cwd(), hostPort: 19997 });
      vi.spyOn(bridge as any, 'request').mockResolvedValue({ status: 'success' });

      await bridge.setScope({
        mode: 'remote',
        targets: ['203.0.113.10'],
        arm_canaries: false,
      });

      await expect(bridge.browserAudit({ url: 'https://evil.com/phish' })).rejects.toThrow(
        'URL is outside the active audit scope'
      );
    });
  });
});
