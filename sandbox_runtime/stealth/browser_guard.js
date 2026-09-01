/**
 * browser_guard.js - L7 URL classification and RoE scope guard for managed browser runtime.
 * Pure Node.js module (zero external dependencies) for SSRF protection and DNS leak prevention.
 */

import dns from 'node:dns/promises';

export function normalizeHost(host) {
  const value = String(host || '').trim().toLowerCase();
  return value.startsWith('[') && value.endsWith(']') ? value.slice(1, -1) : value;
}

export function normalizeAllowedHosts(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(normalizeHost).filter(Boolean))].sort();
}

export function isPrivateOrRestrictedIp(ipStr) {
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

export async function classifyUrl(
  urlStr,
  allowPrivate = false,
  allowedHosts = [],
  isTor = false,
  dnsResolver = dns.lookup
) {
  try {
    const parsed = new URL(urlStr);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return { ok: false, reason: `Unsupported protocol: ${parsed.protocol}` };
    }

    const host = normalizeHost(parsed.hostname);
    if (!host) {
      return { ok: false, reason: 'Missing or empty hostname in URL' };
    }

    if (allowedHosts.length > 0 && !allowedHosts.includes(host)) {
      return { ok: false, reason: `Host is outside active RoE scope: ${host}` };
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
          return { ok: false, reason: `DNS resolves to restricted private IP: ${host} -> ${record.address}` };
        }
      }
    } catch (dnsErr) {
      return { ok: false, reason: `DNS resolution failed for ${host}: ${dnsErr.message}` };
    }

    return { ok: true, reason: 'public' };
  } catch (err) {
    return { ok: false, reason: `URL parse error: ${err.message}` };
  }
}
