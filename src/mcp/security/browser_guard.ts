/**
 * browser_guard.ts - L7 URL classification and RoE scope guard for managed browser runtime.
 * SSRF protection, exact host scoping, and Tor remote DNS leak prevention.
 */

import { lookup } from 'node:dns/promises';

export function normalizeHost(host: string): string {
  const value = String(host || '').trim().toLowerCase();
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

export function normalizeAllowedHosts(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map((v) => String(v || '').trim().toLowerCase()).filter(Boolean))].sort();
}

function parseAllowedAuthority(entry: string): { host: string; port: string | null } {
  const v = String(entry || '').trim().toLowerCase();
  const bracketed = v.match(/^\[([^\]]+)\]:(\d+)$/);
  if (bracketed) return { host: bracketed[1], port: bracketed[2] };
  if (v.startsWith('[') && v.endsWith(']')) return { host: v.slice(1, -1), port: null };
  const colonCount = (v.match(/:/g) || []).length;
  if (colonCount > 1) return { host: v, port: null };
  const idx = v.lastIndexOf(':');
  if (idx !== -1 && /^\d+$/.test(v.slice(idx + 1))) {
    const h = v.slice(0, idx);
    const host = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
    return { host, port: v.slice(idx + 1) };
  }
  const host = v.startsWith('[') && v.endsWith(']') ? v.slice(1, -1) : v;
  return { host, port: null };
}

function effectivePort(protocol: string, explicitPort: string): string {
  if (explicitPort) return explicitPort;
  if (protocol === 'http:') return '80';
  if (protocol === 'https:') return '443';
  return '';
}

function isAuthorityInScope(hostname: string, port: string, allowedHosts: string[]): boolean {
  for (const allowed of allowedHosts) {
    const { host, port: allowedPort } = parseAllowedAuthority(allowed);
    if (host !== hostname) continue;
    if (allowedPort === null) return true;
    if (port && allowedPort === port) return true;
  }
  return false;
}

export function isPrivateOrRestrictedIp(ipStr: string): boolean {
  if (!ipStr) return true;
  const ip = normalizeHost(ipStr);

  if (ip.startsWith('127.') || ip === '0.0.0.0') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith('169.254.')) return true;
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(ip)) return true;
  if (
    ip === '::1' ||
    ip === '::' ||
    ip.startsWith('fe80:') ||
    ip.startsWith('fc00:') ||
    ip.startsWith('fd00:')
  )
    return true;
  if (ip.startsWith('::ffff:') || ip.startsWith('64:ff9b:')) {
    const v4part = ip.split(':').pop();
    if (v4part && isPrivateOrRestrictedIp(v4part)) return true;
  }
  return false;
}

export type DnsLookupFunction = (
  host: string,
  options?: any
) => Promise<Array<{ address: string; family?: number }>>;

export async function classifyUrl(
  urlStr: string,
  allowPrivate = false,
  allowedHosts: string[] = [],
  isTor = false,
  dnsResolver: DnsLookupFunction = lookup as unknown as DnsLookupFunction
): Promise<{ ok: boolean; reason: string }> {
  try {
    const parsed = new URL(urlStr);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, reason: `Unsupported protocol: ${parsed.protocol}` };
    }

    const host = normalizeHost(parsed.hostname);
    if (!host) {
      return { ok: false, reason: 'Missing or empty hostname in URL' };
    }
    const port = effectivePort(parsed.protocol, parsed.port);

    // ROADMAP п.5: explicit host:port scope does not expand to bare host.
    if (allowedHosts.length > 0 && !isAuthorityInScope(host, port, allowedHosts)) {
      return { ok: false, reason: `Host is outside active RoE scope: ${host}${port ? ':' + port : ''}` };
    }

    if (allowPrivate) return { ok: true, reason: 'allow_private' };

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(':')) {
      if (isPrivateOrRestrictedIp(host)) {
        return { ok: false, reason: `Direct private IP access blocked: ${host}` };
      }
    }

    // When Tor transport is active or target is an .onion address, do NOT perform host-side DNS resolution.
    // Hostname resolution happens remotely through the Tor SOCKS circuit to prevent DNS leakage.
    if (isTor || host.endsWith('.onion')) {
      return { ok: true, reason: 'tor_hostname' };
    }

    try {
      const records = await dnsResolver(host, { all: true });
      for (const record of records) {
        if (isPrivateOrRestrictedIp(record.address)) {
          return {
            ok: false,
            reason: `DNS resolves to restricted private IP: ${host} -> ${record.address}`,
          };
        }
      }
    } catch (dnsErr: any) {
      return { ok: false, reason: `DNS resolution failed for ${host}: ${dnsErr?.message || String(dnsErr)}` };
    }

    return { ok: true, reason: 'public' };
  } catch (err: any) {
    return { ok: false, reason: `URL parse error: ${err?.message || String(err)}` };
  }
}
