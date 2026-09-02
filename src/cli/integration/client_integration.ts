import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cliFailureMessage, runClientCli, type ClientCliResult } from './client_cli.js';
import { resolveClientPaths, type ClientPaths } from './client_paths.js';
import {
  SECURITY_AUDIT_MCP_ENTRY,
  SECURITY_AUDIT_SERVER_NAME,
  isSecurityAuditMcpServerEntry,
  isSecurityAuditOpenCodeEntry,
  isSecurityAuditPackageSpec,
  readJsonConfig,
} from './client_registration.js';
import {
  removeCodexSecurityAuditConfig,
  updateCodexSecurityAuditConfig,
} from './codex_config.js';

export type SupportedClient = 'opencode' | 'claude' | 'codex' | 'gemini' | 'antigravity';

export const ALL_SUPPORTED_CLIENTS: readonly SupportedClient[] = Object.freeze([
  'opencode',
  'claude',
  'codex',
  'gemini',
  'antigravity',
]);

type CliRunner = (name: string, args: string[]) => ClientCliResult;

export interface ClientIntegrationOptions {
  clients?: SupportedClient[];
  localAntigravity?: boolean;
  paths?: ClientPaths;
  cliRunner?: CliRunner;
}

export interface IntegrationResult {
  client: SupportedClient;
  status: 'configured' | 'existing' | 'removed' | 'not_found';
  method: 'native' | 'fallback' | 'existing';
  path?: string;
  detail?: string;
}

export function clientsForInstallTarget(target: string): SupportedClient[] {
  switch (String(target || '').toLowerCase()) {
    case 'all':
      return [...ALL_SUPPORTED_CLIENTS];
    case 'agy':
    case 'antigravity':
      return ['antigravity'];
    case 'opencode':
      return ['opencode'];
    case 'claude':
    case 'claude-code':
      return ['claude'];
    case 'codex':
      return ['codex'];
    case 'gemini':
    case 'gemini-cli':
      return ['gemini'];
    default:
      return [];
  }
}

export function findPackageLauncher(): string {
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(currentDir, '../../../../bin/cli.js'),
    resolve(currentDir, '../../../bin/cli.js'),
    resolve(process.cwd(), 'bin/cli.js'),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`security-audit CLI launcher not found: ${candidates.join(', ')}`);
}

async function writeJsonConfig(filePath: string, config: Record<string, any>): Promise<void> {
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

export async function configureJsonMcpClient({
  label,
  cliName,
  cliArgs,
  configPath,
  cliRunner = runClientCli,
}: {
  label: string;
  cliName: string;
  cliArgs: string[];
  configPath: string;
  cliRunner?: CliRunner;
}): Promise<{ method: 'native' | 'fallback' | 'existing'; configPath: string; nativeReason?: string }> {
  let config = await readJsonConfig(configPath);
  const existing = config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME];
  if (existing && !isSecurityAuditMcpServerEntry(existing)) {
    throw new Error(`Existing mcpServers.${SECURITY_AUDIT_SERVER_NAME} in ${configPath} is not owned by this plugin`);
  }
  if (existing) return { method: 'existing', configPath };

  const native = cliRunner(cliName, cliArgs);
  if (native.ok) {
    config = await readJsonConfig(configPath);
    if (isSecurityAuditMcpServerEntry(config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME])) {
      return { method: 'native', configPath };
    }
  }

  config = await readJsonConfig(configPath);
  const afterNative = config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME];
  if (afterNative && !isSecurityAuditMcpServerEntry(afterNative)) {
    throw new Error(`Native ${label} setup created an unrecognized ${SECURITY_AUDIT_SERVER_NAME} entry in ${configPath}`);
  }
  if (!config.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers)) {
    config.mcpServers = {};
  }
  config.mcpServers[SECURITY_AUDIT_SERVER_NAME] = {
    command: SECURITY_AUDIT_MCP_ENTRY.command,
    args: [...SECURITY_AUDIT_MCP_ENTRY.args],
  };
  await writeJsonConfig(configPath, config);
  return {
    method: 'fallback',
    configPath,
    nativeReason: native.ok ? 'native command did not create the expected entry' : cliFailureMessage(native),
  };
}

function getOpenCodeServerContainer(config: Record<string, any>): Record<string, any> {
  if (config.mcp === undefined) {
    config.mcp = {};
    return config.mcp;
  }
  if (!config.mcp || typeof config.mcp !== 'object' || Array.isArray(config.mcp)) {
    throw new Error('OpenCode config field "mcp" exists but is not an object');
  }
  if (config.mcp.servers !== undefined) {
    if (!config.mcp.servers || typeof config.mcp.servers !== 'object' || Array.isArray(config.mcp.servers)) {
      throw new Error('OpenCode config field "mcp.servers" exists but is not an object');
    }
    return config.mcp.servers;
  }
  return config.mcp;
}

async function configureOpenCode(paths: ClientPaths): Promise<IntegrationResult> {
  const config = await readJsonConfig(paths.opencodeConfigPath);
  const servers = getOpenCodeServerContainer(config);
  const existing = servers[SECURITY_AUDIT_SERVER_NAME];
  if (existing && !isSecurityAuditOpenCodeEntry(existing)) {
    throw new Error(`Existing OpenCode MCP entry ${SECURITY_AUDIT_SERVER_NAME} is not owned by this plugin`);
  }
  if (existing) {
    return { client: 'opencode', status: 'existing', method: 'existing', path: paths.opencodeConfigPath };
  }

  servers[SECURITY_AUDIT_SERVER_NAME] = {
    type: 'local',
    command: ['npx', '-y', '@security-audit/plugin', 'mcp'],
  };
  await writeJsonConfig(paths.opencodeConfigPath, config);
  return { client: 'opencode', status: 'configured', method: 'fallback', path: paths.opencodeConfigPath };
}

async function configureAntigravity(paths: ClientPaths, localRequested: boolean): Promise<IntegrationResult> {
  const configureOne = async (configPath: string) => {
    const config = await readJsonConfig(configPath);
    if (!config.mcpServers || typeof config.mcpServers !== 'object' || Array.isArray(config.mcpServers)) {
      config.mcpServers = {};
    }
    const existing = config.mcpServers[SECURITY_AUDIT_SERVER_NAME];
    if (existing && !isSecurityAuditMcpServerEntry(existing)) {
      throw new Error(`Existing Antigravity MCP entry in ${configPath} is not owned by this plugin`);
    }
    config.mcpServers[SECURITY_AUDIT_SERVER_NAME] = {
      command: SECURITY_AUDIT_MCP_ENTRY.command,
      args: [...SECURITY_AUDIT_MCP_ENTRY.args],
    };
    await writeJsonConfig(configPath, config);
  };

  await configureOne(paths.antigravityMcpConfigPath);
  if (localRequested || existsSync(paths.localAgentsDir)) {
    await configureOne(paths.localAgentsMcpConfigPath);
  }
  return {
    client: 'antigravity',
    status: 'configured',
    method: 'fallback',
    path: paths.antigravityMcpConfigPath,
  };
}

async function configureCodex(paths: ClientPaths, cliRunner: CliRunner): Promise<IntegrationResult> {
  const launcherPath = findPackageLauncher();
  const nodePath = process.execPath;
  await mkdir(paths.codexDir, { recursive: true });
  let content = existsSync(paths.codexConfigPath) ? await readFile(paths.codexConfigPath, 'utf-8') : '';
  let update = updateCodexSecurityAuditConfig(content, { nodePath, launcherPath });
  if (update.status === 'conflict') throw new Error(update.reason);

  let nativeReason: string | undefined;
  if (update.status === 'added') {
    const native = cliRunner('codex', [
      'mcp',
      'add',
      SECURITY_AUDIT_SERVER_NAME,
      '--',
      nodePath,
      launcherPath,
      'mcp',
    ]);
    if (native.ok) {
      content = existsSync(paths.codexConfigPath) ? await readFile(paths.codexConfigPath, 'utf-8') : '';
      update = updateCodexSecurityAuditConfig(content, { nodePath, launcherPath });
      if (update.status === 'conflict') throw new Error(update.reason);
    } else {
      nativeReason = cliFailureMessage(native);
    }
  }

  if (update.changed) {
    await writeFile(paths.codexConfigPath, update.content, 'utf-8');
  }
  return {
    client: 'codex',
    status: update.status === 'unchanged' ? 'existing' : 'configured',
    method: nativeReason ? 'fallback' : update.status === 'unchanged' ? 'existing' : 'native',
    path: paths.codexConfigPath,
    detail: nativeReason,
  };
}

export async function setupClientIntegrations({
  clients = [...ALL_SUPPORTED_CLIENTS],
  localAntigravity = false,
  paths = resolveClientPaths(),
  cliRunner = runClientCli,
}: ClientIntegrationOptions = {}): Promise<IntegrationResult[]> {
  const results: IntegrationResult[] = [];
  for (const client of clients) {
    if (client === 'opencode') {
      results.push(await configureOpenCode(paths));
    } else if (client === 'claude') {
      const result = await configureJsonMcpClient({
        label: 'Claude Code',
        cliName: 'claude',
        cliArgs: ['mcp', 'add', '--scope', 'user', SECURITY_AUDIT_SERVER_NAME, '--', 'npx', '-y', '@security-audit/plugin', 'mcp'],
        configPath: paths.claudeConfigPath,
        cliRunner,
      });
      results.push({ client, status: result.method === 'existing' ? 'existing' : 'configured', method: result.method, path: result.configPath, detail: result.nativeReason });
    } else if (client === 'gemini') {
      const result = await configureJsonMcpClient({
        label: 'Gemini CLI',
        cliName: 'gemini',
        cliArgs: ['mcp', 'add', '--scope', 'user', SECURITY_AUDIT_SERVER_NAME, 'npx', '--', '-y', '@security-audit/plugin', 'mcp'],
        configPath: paths.geminiSettingsPath,
        cliRunner,
      });
      results.push({ client, status: result.method === 'existing' ? 'existing' : 'configured', method: result.method, path: result.configPath, detail: result.nativeReason });
    } else if (client === 'antigravity') {
      results.push(await configureAntigravity(paths, localAntigravity));
    } else if (client === 'codex') {
      results.push(await configureCodex(paths, cliRunner));
    }
  }
  return results;
}

async function removeJsonMcpClient({
  label,
  configPath,
  cliName,
  cliArgs,
  cliRunner,
}: {
  label: string;
  configPath: string;
  cliName: string;
  cliArgs: string[];
  cliRunner: CliRunner;
}): Promise<{ status: 'removed' | 'not_found'; method: 'native' | 'fallback'; detail?: string }> {
  if (!existsSync(configPath)) return { status: 'not_found', method: 'fallback' };
  let config = await readJsonConfig(configPath);
  const entry = config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME];
  if (!entry) return { status: 'not_found', method: 'fallback' };
  if (!isSecurityAuditMcpServerEntry(entry)) {
    throw new Error(`Existing ${label} ${SECURITY_AUDIT_SERVER_NAME} entry is not owned by this plugin`);
  }

  const native = cliRunner(cliName, cliArgs);
  if (native.ok) {
    config = await readJsonConfig(configPath);
    if (!config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME]) {
      return { status: 'removed', method: 'native' };
    }
    if (!isSecurityAuditMcpServerEntry(config.mcpServers[SECURITY_AUDIT_SERVER_NAME])) {
      throw new Error(`Native ${label} removal left an unrecognized ${SECURITY_AUDIT_SERVER_NAME} entry`);
    }
  }

  config = await readJsonConfig(configPath);
  if (config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME]) {
    delete config.mcpServers[SECURITY_AUDIT_SERVER_NAME];
    await writeJsonConfig(configPath, config);
  }
  return {
    status: 'removed',
    method: 'fallback',
    detail: native.ok ? 'native command did not remove the expected entry' : cliFailureMessage(native),
  };
}

async function removeOpenCode(paths: ClientPaths): Promise<IntegrationResult> {
  if (!existsSync(paths.opencodeConfigPath)) {
    return { client: 'opencode', status: 'not_found', method: 'fallback', path: paths.opencodeConfigPath };
  }
  const config = await readJsonConfig(paths.opencodeConfigPath);
  let removed = false;

  if (config.mcp && typeof config.mcp === 'object' && !Array.isArray(config.mcp)) {
    const containers: Record<string, any>[] = [];
    if (config.mcp.servers && typeof config.mcp.servers === 'object' && !Array.isArray(config.mcp.servers)) {
      containers.push(config.mcp.servers);
    }
    containers.push(config.mcp);
    for (const container of containers) {
      const entry = container[SECURITY_AUDIT_SERVER_NAME];
      if (!entry) continue;
      if (!isSecurityAuditOpenCodeEntry(entry)) {
        throw new Error(`Existing OpenCode MCP entry ${SECURITY_AUDIT_SERVER_NAME} is not owned by this plugin`);
      }
      delete container[SECURITY_AUDIT_SERVER_NAME];
      removed = true;
    }
  }

  for (const field of ['plugin', 'plugins']) {
    if (!Array.isArray(config[field])) continue;
    const next = config[field].filter((entry: unknown) => !isSecurityAuditPackageSpec(entry));
    if (next.length !== config[field].length) removed = true;
    if (next.length === 0) delete config[field];
    else config[field] = next;
  }

  if (removed) await writeJsonConfig(paths.opencodeConfigPath, config);
  return {
    client: 'opencode',
    status: removed ? 'removed' : 'not_found',
    method: 'fallback',
    path: paths.opencodeConfigPath,
  };
}

async function removeAntigravity(paths: ClientPaths): Promise<IntegrationResult> {
  let removed = false;
  for (const configPath of [paths.antigravityMcpConfigPath, paths.localAgentsMcpConfigPath]) {
    if (!existsSync(configPath)) continue;
    const config = await readJsonConfig(configPath);
    const entry = config.mcpServers?.[SECURITY_AUDIT_SERVER_NAME];
    if (!entry) continue;
    if (!isSecurityAuditMcpServerEntry(entry)) {
      throw new Error(`Existing Antigravity MCP entry in ${configPath} is not owned by this plugin`);
    }
    delete config.mcpServers[SECURITY_AUDIT_SERVER_NAME];
    await writeJsonConfig(configPath, config);
    removed = true;
  }
  return {
    client: 'antigravity',
    status: removed ? 'removed' : 'not_found',
    method: 'fallback',
    path: paths.antigravityMcpConfigPath,
  };
}

async function removeCodex(paths: ClientPaths, cliRunner: CliRunner): Promise<IntegrationResult> {
  if (!existsSync(paths.codexConfigPath)) {
    return { client: 'codex', status: 'not_found', method: 'fallback', path: paths.codexConfigPath };
  }
  let content = await readFile(paths.codexConfigPath, 'utf-8');
  let removal = removeCodexSecurityAuditConfig(content);
  if (removal.status === 'conflict') throw new Error(removal.reason);
  if (removal.status === 'not_found') {
    return { client: 'codex', status: 'not_found', method: 'fallback', path: paths.codexConfigPath };
  }

  const native = cliRunner('codex', ['mcp', 'remove', SECURITY_AUDIT_SERVER_NAME]);
  if (native.ok) {
    content = existsSync(paths.codexConfigPath) ? await readFile(paths.codexConfigPath, 'utf-8') : '';
    removal = removeCodexSecurityAuditConfig(content);
    if (removal.status === 'not_found') {
      return { client: 'codex', status: 'removed', method: 'native', path: paths.codexConfigPath };
    }
    if (removal.status === 'conflict') throw new Error(removal.reason);
  }
  if (removal.changed) await writeFile(paths.codexConfigPath, removal.content, 'utf-8');
  return {
    client: 'codex',
    status: 'removed',
    method: 'fallback',
    path: paths.codexConfigPath,
    detail: native.ok ? 'native command did not remove the expected section' : cliFailureMessage(native),
  };
}

export async function removeClientIntegrations({
  clients = [...ALL_SUPPORTED_CLIENTS],
  paths = resolveClientPaths(),
  cliRunner = runClientCli,
}: Omit<ClientIntegrationOptions, 'localAntigravity'> = {}): Promise<IntegrationResult[]> {
  const results: IntegrationResult[] = [];
  for (const client of clients) {
    if (client === 'opencode') {
      results.push(await removeOpenCode(paths));
    } else if (client === 'antigravity') {
      results.push(await removeAntigravity(paths));
    } else if (client === 'claude') {
      const result = await removeJsonMcpClient({
        label: 'Claude Code',
        configPath: paths.claudeConfigPath,
        cliName: 'claude',
        cliArgs: ['mcp', 'remove', '--scope', 'user', SECURITY_AUDIT_SERVER_NAME],
        cliRunner,
      });
      results.push({ client, status: result.status, method: result.method, path: paths.claudeConfigPath, detail: result.detail });
    } else if (client === 'gemini') {
      const result = await removeJsonMcpClient({
        label: 'Gemini CLI',
        configPath: paths.geminiSettingsPath,
        cliName: 'gemini',
        cliArgs: ['mcp', 'remove', '--scope', 'user', SECURITY_AUDIT_SERVER_NAME],
        cliRunner,
      });
      results.push({ client, status: result.status, method: result.method, path: paths.geminiSettingsPath, detail: result.detail });
    } else if (client === 'codex') {
      results.push(await removeCodex(paths, cliRunner));
    }
  }
  return results;
}
