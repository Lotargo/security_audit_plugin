import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

export const SECURITY_AUDIT_SERVER_NAME = 'security-audit-sandbox';

export const SECURITY_AUDIT_MCP_ENTRY = Object.freeze({
  command: 'npx',
  args: Object.freeze(['-y', '@security-audit/plugin', 'mcp']),
});

function normalize(value: unknown): string {
  return String(value || '').replace(/\\/g, '/').toLowerCase();
}

export function isSecurityAuditPackageSpec(value: unknown): boolean {
  const spec = normalize(value);
  return /^@security-audit\/plugin(?:@[^/]+)?$/i.test(spec)
    || /^security-audit-plugin(?:@[^/]+)?$/i.test(spec)
    || /security[_-]audit[_-]plugin(?:\.git)?(?:#.*)?$/i.test(spec);
}

export function isSecurityAuditMcpServerEntry(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const object = entry as Record<string, unknown>;
  const command = normalize(object.command);
  const args = Array.isArray(object.args) ? object.args.map(normalize) : [];

  const packageArg = args.some((arg) => /^@security-audit\/plugin(?:@[^/]+)?$/i.test(arg));
  const hasMcpArg = args.includes('mcp');
  const directBinary = /(?:^|\/)(?:security-audit|security-audit-plugin)(?:\.(?:cmd|exe|ps1|bat))?$/i.test(command);
  const nodeLauncher = /(?:^|\/)node(?:\.exe)?$/i.test(command)
    && args.some((arg) => arg.endsWith('/bin/cli.js'))
    && hasMcpArg;

  return (packageArg && hasMcpArg) || (directBinary && hasMcpArg) || nodeLauncher;
}

export function isSecurityAuditOpenCodeEntry(entry: unknown): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const object = entry as Record<string, unknown>;
  if (object.type !== undefined && object.type !== 'local') return false;
  if (!Array.isArray(object.command)) return false;
  const command = object.command.map(normalize);
  const packageArg = command.some((arg) => /^@security-audit\/plugin(?:@[^/]+)?$/i.test(arg));
  const hasMcpArg = command.includes('mcp');
  const directBinary = command.some((arg) => /(?:^|\/)(?:security-audit|security-audit-plugin)(?:\.(?:cmd|exe|ps1|bat))?$/i.test(arg));
  const nodeLauncher = command.some((arg) => /(?:^|\/)node(?:\.exe)?$/i.test(arg))
    && command.some((arg) => arg.endsWith('/bin/cli.js'));
  return hasMcpArg && (packageArg || directBinary || nodeLauncher);
}

export async function readJsonConfig(filePath: string): Promise<Record<string, any>> {
  if (!existsSync(filePath)) return {};
  const raw = (await readFile(filePath, 'utf-8')).replace(/^\uFEFF/, '');
  const value = JSON.parse(raw);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Expected a JSON object in ${filePath}`);
  }
  return value as Record<string, any>;
}
