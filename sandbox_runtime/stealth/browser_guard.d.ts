export function normalizeHost(host: string): string;
export function normalizeAllowedHosts(value: unknown): string[];
export function isPrivateOrRestrictedIp(ipStr: string): boolean;
export function classifyUrl(
  urlStr: string,
  allowPrivate?: boolean,
  allowedHosts?: string[],
  isTor?: boolean,
  dnsResolver?: (host: string, options?: any) => Promise<Array<{ address: string; family?: number }>>
): Promise<{ ok: boolean; reason: string }>;
