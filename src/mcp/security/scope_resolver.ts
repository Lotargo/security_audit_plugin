import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export type HostResolver = (hostname: string) => Promise<string[]>;

function stripIpv6Brackets(value: string): string {
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

/** Normalize an IP or CIDR to an explicit network specification. */
export function normalizeIpSpec(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  const slash = trimmed.lastIndexOf('/');
  if (slash !== -1) {
    const rawAddress = stripIpv6Brackets(trimmed.slice(0, slash));
    const rawPrefix = trimmed.slice(slash + 1);
    const family = isIP(rawAddress);
    if (!family || !/^\d+$/.test(rawPrefix)) return null;

    const prefix = Number(rawPrefix);
    const maxPrefix = family === 4 ? 32 : 128;
    if (prefix < 0 || prefix > maxPrefix) return null;
    return `${rawAddress}/${prefix}`;
  }

  const rawAddress = stripIpv6Brackets(trimmed);
  const family = isIP(rawAddress);
  if (!family) return null;
  return `${rawAddress}/${family === 4 ? 32 : 128}`;
}

export function extractTargetHostname(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) throw new Error('Scope target cannot be empty');

  const directIp = normalizeIpSpec(trimmed);
  if (directIp) return directIp.split('/')[0];

  try {
    const parsed = new URL(trimmed.includes('://') ? trimmed : `http://${trimmed}`);
    const hostname = stripIpv6Brackets(parsed.hostname);
    if (!hostname) throw new Error('missing hostname');
    return hostname;
  } catch {
    throw new Error(`Invalid scope target: ${target}`);
  }
}

export const defaultHostResolver: HostResolver = async (hostname: string) => {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map((answer) => answer.address);
};

/**
 * Resolve user-facing scope targets once on the trusted host and pin the resulting addresses.
 * This makes nftables the final authority instead of relying on an L7-only hostname check.
 */
export async function resolveScopeTargets(
  targets: string[],
  resolveHost: HostResolver = defaultHostResolver
): Promise<string[]> {
  const resolved = new Set<string>();

  for (const target of targets) {
    const direct = normalizeIpSpec(target);
    if (direct) {
      resolved.add(direct);
      continue;
    }

    const hostname = extractTargetHostname(target);
    const hostIp = normalizeIpSpec(hostname);
    if (hostIp) {
      resolved.add(hostIp);
      continue;
    }

    let addresses: string[];
    try {
      addresses = await resolveHost(hostname);
    } catch (err: any) {
      throw new Error(`Failed to resolve scope target ${hostname}: ${err?.message || String(err)}`);
    }

    if (addresses.length === 0) {
      throw new Error(`Scope target ${hostname} resolved to no addresses`);
    }

    for (const address of addresses) {
      const normalized = normalizeIpSpec(address);
      if (!normalized) {
        throw new Error(`Resolver returned an invalid address for ${hostname}: ${address}`);
      }
      resolved.add(normalized);
    }
  }

  return [...resolved].sort();
}

export function normalizeCidrList(values: string[], label: string): string[] {
  const normalized = new Set<string>();
  for (const value of values) {
    const spec = normalizeIpSpec(value);
    if (!spec) throw new Error(`Invalid ${label} entry: ${value}`);
    normalized.add(spec);
  }
  return [...normalized].sort();
}

/**
 * Produce the exact L7 hostname allowlist used by managed proxy/Tor clients.
 * Broad CIDRs are intentionally rejected here: once traffic is tunneled through a proxy the
 * sandbox kernel can see only the proxy endpoint, so a network CIDR cannot be enforced reliably.
 */
export function normalizeScopeHosts(targets: string[]): string[] {
  const hosts = new Set<string>();

  for (const target of targets) {
    const trimmed = target.trim();
    if (!trimmed) throw new Error('Scope target cannot be empty');

    const direct = normalizeIpSpec(trimmed);
    if (direct) {
      const [address, prefixText] = direct.split('/');
      const family = isIP(address);
      const hostPrefix = family === 4 ? 32 : 128;
      if (Number(prefixText) !== hostPrefix) {
        throw new Error(
          `Proxy/Tor scope target must be a single host, not a broad CIDR: ${target}`
        );
      }
      hosts.add(address.toLowerCase());
      continue;
    }

    hosts.add(extractTargetHostname(trimmed).toLowerCase());
  }

  return [...hosts].sort();
}

export function isUrlInScope(url: string, allowedHosts: string[]): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    const hostname = stripIpv6Brackets(parsed.hostname).toLowerCase();
    return allowedHosts.some((allowed) => allowed.toLowerCase() === hostname);
  } catch {
    return false;
  }
}
