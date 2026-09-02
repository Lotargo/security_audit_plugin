import * as os from 'node:os';
import * as path from 'node:path';

export interface ClientPathsOptions {
  home?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
}

export interface ClientPaths {
  home: string;
  cwd: string;
  configHome: string;
  opencodeDir: string;
  opencodeConfigPath: string;
  claudeConfigPath: string;
  geminiDir: string;
  geminiSettingsPath: string;
  antigravityConfigDir: string;
  antigravityMcpConfigPath: string;
  localAgentsDir: string;
  localAgentsMcpConfigPath: string;
  codexDir: string;
  codexConfigPath: string;
}

export function resolveClientPaths({
  home = os.homedir(),
  cwd = process.cwd(),
  env = process.env,
}: ClientPathsOptions = {}): ClientPaths {
  const configHome = env.XDG_CONFIG_HOME || path.join(home, '.config');
  const opencodeDir = env.OPENCODE_CONFIG_DIR || path.join(configHome, 'opencode');
  const geminiDir = path.join(home, '.gemini');
  const antigravityConfigDir = path.join(geminiDir, 'config');

  return {
    home,
    cwd,
    configHome,
    opencodeDir,
    opencodeConfigPath: path.join(opencodeDir, 'opencode.json'),
    claudeConfigPath: path.join(home, '.claude.json'),
    geminiDir,
    geminiSettingsPath: path.join(geminiDir, 'settings.json'),
    antigravityConfigDir,
    antigravityMcpConfigPath: path.join(antigravityConfigDir, 'mcp_config.json'),
    localAgentsDir: path.join(cwd, '.agents'),
    localAgentsMcpConfigPath: path.join(cwd, '.agents', 'mcp_config.json'),
    codexDir: path.join(home, '.codex'),
    codexConfigPath: path.join(home, '.codex', 'config.toml'),
  };
}
