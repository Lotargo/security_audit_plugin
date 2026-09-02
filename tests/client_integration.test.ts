import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveClientPaths } from '../src/cli/integration/client_paths.js';
import {
  SECURITY_AUDIT_SERVER_NAME,
  isSecurityAuditMcpServerEntry,
  isSecurityAuditOpenCodeEntry,
  readJsonConfig,
} from '../src/cli/integration/client_registration.js';
import {
  removeCodexSecurityAuditConfig,
  updateCodexSecurityAuditConfig,
} from '../src/cli/integration/codex_config.js';
import {
  configureJsonMcpClient,
  removeClientIntegrations,
  setupClientIntegrations,
} from '../src/cli/integration/client_integration.js';
import { parseCodexSecurityAuditConfig } from '../src/cli/integration/client_diagnostics.js';
import type { ClientCliResult } from '../src/cli/integration/client_cli.js';

function unavailableCli(): ClientCliResult {
  return {
    available: false,
    ok: false,
    status: null,
    executable: null,
    stdout: '',
    stderr: '',
    error: null,
  };
}

describe('client CLI integration layer', () => {
  let tmpDir: string;
  let home: string;
  let cwd: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-client-integration-'));
    home = path.join(tmpDir, 'home');
    cwd = path.join(tmpDir, 'workspace');
    fs.mkdirSync(home, { recursive: true });
    fs.mkdirSync(cwd, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('resolves isolated client config paths without touching provider authentication', () => {
    const paths = resolveClientPaths({ home, cwd, env: {} });
    expect(paths.opencodeConfigPath).toBe(path.join(home, '.config', 'opencode', 'opencode.json'));
    expect(paths.claudeConfigPath).toBe(path.join(home, '.claude.json'));
    expect(paths.geminiSettingsPath).toBe(path.join(home, '.gemini', 'settings.json'));
    expect(paths.antigravityMcpConfigPath).toBe(path.join(home, '.gemini', 'config', 'mcp_config.json'));
    expect(paths.codexConfigPath).toBe(path.join(home, '.codex', 'config.toml'));
  });

  it('recognizes only plugin-owned stdio registrations', () => {
    expect(isSecurityAuditMcpServerEntry({
      command: 'npx',
      args: ['-y', '@security-audit/plugin', 'mcp'],
    })).toBe(true);
    expect(isSecurityAuditMcpServerEntry({ command: 'npx', args: ['-y', '@other/tool'] })).toBe(false);
    expect(isSecurityAuditOpenCodeEntry({
      type: 'local',
      command: ['npx', '-y', '@security-audit/plugin', 'mcp'],
    })).toBe(true);
  });

  it('adds, normalizes and removes the owned Codex TOML section while preserving unrelated config', () => {
    const original = '[features]\nfoo = true\n';
    const options = { nodePath: '/usr/bin/node', launcherPath: '/opt/security/bin/cli.js' };
    const added = updateCodexSecurityAuditConfig(original, options);
    expect(added.status).toBe('added');
    expect(added.content).toContain('[mcp_servers.security-audit-sandbox]');
    expect(added.content).toContain('[features]');

    const parsed = parseCodexSecurityAuditConfig(added.content);
    expect(parsed.ok).toBe(true);
    expect(parsed.command).toBe('/usr/bin/node');
    expect(parsed.args).toEqual(['/opt/security/bin/cli.js', 'mcp']);

    const normalized = updateCodexSecurityAuditConfig(added.content, options);
    expect(normalized.status).toBe('unchanged');

    const removed = removeCodexSecurityAuditConfig(added.content);
    expect(removed.status).toBe('removed');
    expect(removed.content).toContain('[features]');
    expect(removed.content).not.toContain('security-audit-sandbox');
  });

  it('refuses to overwrite a foreign Codex registration with the same server name', () => {
    const foreign = '[mcp_servers.security-audit-sandbox]\ncommand = "foreign-tool"\nargs = []\n';
    const result = updateCodexSecurityAuditConfig(foreign, {
      nodePath: '/usr/bin/node',
      launcherPath: '/opt/security/bin/cli.js',
    });
    expect(result.status).toBe('conflict');
  });

  it('uses an ownership-checked JSON fallback when the native client CLI is unavailable', async () => {
    const configPath = path.join(tmpDir, 'claude.json');
    const result = await configureJsonMcpClient({
      label: 'Claude Code',
      cliName: 'claude',
      cliArgs: ['mcp', 'add'],
      configPath,
      cliRunner: unavailableCli,
    });
    expect(result.method).toBe('fallback');
    const config = await readJsonConfig(configPath);
    expect(config.mcpServers[SECURITY_AUDIT_SERVER_NAME]).toEqual({
      command: 'npx',
      args: ['-y', '@security-audit/plugin', 'mcp'],
    });

    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: {
        [SECURITY_AUDIT_SERVER_NAME]: { command: 'foreign', args: [] },
      },
    }));
    await expect(configureJsonMcpClient({
      label: 'Claude Code',
      cliName: 'claude',
      cliArgs: ['mcp', 'add'],
      configPath,
      cliRunner: unavailableCli,
    })).rejects.toThrow('is not owned by this plugin');
  });

  it('configures OpenCode, Claude, Gemini, Antigravity and Codex without storing client credentials', async () => {
    const paths = resolveClientPaths({ home, cwd, env: {} });
    fs.mkdirSync(paths.localAgentsDir, { recursive: true });

    const results = await setupClientIntegrations({
      clients: ['opencode', 'claude', 'gemini', 'antigravity', 'codex'],
      localAntigravity: true,
      paths,
      cliRunner: unavailableCli,
    });
    expect(results).toHaveLength(5);

    const openCode = await readJsonConfig(paths.opencodeConfigPath);
    expect(isSecurityAuditOpenCodeEntry(openCode.mcp[SECURITY_AUDIT_SERVER_NAME])).toBe(true);

    const claude = await readJsonConfig(paths.claudeConfigPath);
    const gemini = await readJsonConfig(paths.geminiSettingsPath);
    const agy = await readJsonConfig(paths.antigravityMcpConfigPath);
    const localAgy = await readJsonConfig(paths.localAgentsMcpConfigPath);
    for (const config of [claude, gemini, agy, localAgy]) {
      expect(isSecurityAuditMcpServerEntry(config.mcpServers[SECURITY_AUDIT_SERVER_NAME])).toBe(true);
      expect(JSON.stringify(config)).not.toMatch(/token|api[_-]?key|oauth/i);
    }

    const codex = fs.readFileSync(paths.codexConfigPath, 'utf8');
    expect(codex).toContain('[mcp_servers.security-audit-sandbox]');
    expect(parseCodexSecurityAuditConfig(codex).ok).toBe(true);
  });

  it('removes only owned client registrations and leaves unrelated entries intact', async () => {
    const paths = resolveClientPaths({ home, cwd, env: {} });
    await setupClientIntegrations({
      clients: ['opencode', 'claude', 'codex'],
      paths,
      cliRunner: unavailableCli,
    });

    const claude = await readJsonConfig(paths.claudeConfigPath);
    claude.mcpServers.unrelated = { command: 'other', args: [] };
    fs.writeFileSync(paths.claudeConfigPath, JSON.stringify(claude, null, 2));

    const results = await removeClientIntegrations({
      clients: ['opencode', 'claude', 'codex'],
      paths,
      cliRunner: unavailableCli,
    });
    expect(results.every((result) => result.status === 'removed')).toBe(true);

    const afterClaude = await readJsonConfig(paths.claudeConfigPath);
    expect(afterClaude.mcpServers[SECURITY_AUDIT_SERVER_NAME]).toBeUndefined();
    expect(afterClaude.mcpServers.unrelated).toEqual({ command: 'other', args: [] });
    expect(fs.readFileSync(paths.codexConfigPath, 'utf8')).not.toContain('security-audit-sandbox');
  });
});
