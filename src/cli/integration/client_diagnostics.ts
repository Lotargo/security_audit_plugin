import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { getCodexSecurityAuditSections } from './codex_config.js';
import { resolveClientPaths } from './client_paths.js';

function decodeTomlString(raw: string | undefined): string | null {
  const value = String(raw || '').trim();
  if (value.startsWith('"')) {
    try {
      return JSON.parse(value) as string;
    } catch {
      return null;
    }
  }
  if (value.startsWith("'") && value.endsWith("'")) return value.slice(1, -1).replace(/''/g, "'");
  return null;
}

export function parseCodexSecurityAuditConfig(content: string): {
  ok: boolean;
  error?: string;
  command?: string;
  args?: string[];
  startupTimeoutSec?: number | null;
  sectionCount: number;
} {
  const exact = getCodexSecurityAuditSections(content).filter((section) => section.exact);
  if (exact.length !== 1) {
    return {
      ok: false,
      error: exact.length === 0
        ? '[mcp_servers.security-audit-sandbox] section not found'
        : `Found ${exact.length} security-audit-sandbox sections`,
      sectionCount: exact.length,
    };
  }

  const text = exact[0].text;
  const commandMatch = text.match(/^\s*command\s*=\s*(.+?)\s*$/m);
  const argsMatch = text.match(/^\s*args\s*=\s*\[([\s\S]*?)\]\s*$/m);
  const timeoutMatch = text.match(/^\s*startup_timeout_sec\s*=\s*(\d+)\s*$/m);
  const command = decodeTomlString(commandMatch?.[1]);
  const args: string[] = [];
  if (argsMatch) {
    const stringPattern = /"(?:\\.|[^"\\])*"|'(?:''|[^'])*'/g;
    for (const match of argsMatch[1].matchAll(stringPattern)) {
      const decoded = decodeTomlString(match[0]);
      if (decoded === null) return { ok: false, error: 'Unable to parse security-audit-sandbox args', sectionCount: 1 };
      args.push(decoded);
    }
  }

  if (!command) return { ok: false, error: 'Unable to parse security-audit-sandbox command', sectionCount: 1 };
  if (!argsMatch) return { ok: false, error: 'Unable to parse security-audit-sandbox args', sectionCount: 1 };
  return {
    ok: true,
    command,
    args,
    startupTimeoutSec: timeoutMatch ? Number(timeoutMatch[1]) : null,
    sectionCount: 1,
  };
}

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason?: any) => void;
}

export async function runDirectMcpSmoke({
  command,
  args = [],
  cwd = process.cwd(),
  env = process.env,
  timeoutMs = 120_000,
}: {
  command: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}): Promise<{ ok: true; toolNames: string[]; stderr: string }> {
  if (!command) throw new Error('MCP command is required');
  const child = spawn(command, args, { cwd, env: { ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');

  let nextId = 0;
  let stdoutBuffer = '';
  let stderr = '';
  let settled = false;
  const pending = new Map<number, PendingRequest>();

  const rejectAll = (error: Error) => {
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  };

  child.stderr.on('data', (chunk: string) => { stderr += chunk; });
  child.stdout.on('data', (chunk: string) => {
    stdoutBuffer += chunk;
    let newline: number;
    while ((newline = stdoutBuffer.indexOf('\n')) >= 0) {
      const line = stdoutBuffer.slice(0, newline).trim();
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (!line) continue;
      let message: any;
      try {
        message = JSON.parse(line);
      } catch (error) {
        rejectAll(new Error(`Invalid JSON-RPC output: ${(error as Error).message}; line=${line.slice(0, 200)}`));
        continue;
      }
      const waiter = pending.get(message.id);
      if (!waiter) continue;
      pending.delete(message.id);
      if (message.error) waiter.reject(new Error(message.error.message || JSON.stringify(message.error)));
      else waiter.resolve(message.result);
    }
  });
  child.on('error', (error) => rejectAll(error));
  child.on('exit', (code, signal) => {
    if (!settled && pending.size > 0) {
      rejectAll(new Error(`MCP server exited before diagnostics completed (code=${code}, signal=${signal}): ${stderr.trim()}`));
    }
  });

  const request = (method: string, params: Record<string, any> = {}): Promise<any> => {
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  };

  const withTimeout = <T>(promise: Promise<T>, label: string): Promise<T> => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${label} after ${timeoutMs}ms`)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); }
    );
  });

  try {
    await withTimeout(request('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'security-audit-codex-doctor', version: '1.0.0' },
    }), 'initialize');
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} }) + '\n');

    const toolsResult = await withTimeout(request('tools/list'), 'tools/list');
    const toolNames = (toolsResult?.tools || []).map((tool: any) => String(tool.name));
    for (const required of ['sandbox_set_scope', 'sandbox_exec', 'sandbox_kill_switch']) {
      if (!toolNames.includes(required)) throw new Error(`Required MCP tool is missing: ${required}`);
    }
    settled = true;
    return { ok: true, toolNames, stderr: stderr.trim() };
  } finally {
    settled = true;
    rejectAll(new Error('MCP diagnostics finished'));
    if (child.exitCode === null) child.kill();
  }
}

export async function runCodexDoctor({
  home,
  cwd = process.cwd(),
  env = process.env,
  output = console,
}: {
  home?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  output?: Pick<Console, 'log'>;
} = {}): Promise<boolean> {
  const paths = resolveClientPaths({ home, cwd, env });
  if (!existsSync(paths.codexConfigPath)) {
    output.log(`[FAIL] Codex config not found: ${paths.codexConfigPath}`);
    return false;
  }

  const parsed = parseCodexSecurityAuditConfig(readFileSync(paths.codexConfigPath, 'utf8'));
  if (!parsed.ok || !parsed.command || !parsed.args) {
    output.log(`[FAIL] Codex security-audit-sandbox config: ${parsed.error}`);
    return false;
  }

  let ok = true;
  output.log(`[OK] Codex security-audit-sandbox section: ${paths.codexConfigPath}`);
  if (/\bnpx(?:\.cmd)?$/i.test(parsed.command)) {
    output.log(`[FAIL] Codex launcher still uses npx instead of a direct Node executable: ${parsed.command}`);
    ok = false;
  } else {
    output.log(`[OK] Codex direct executable launcher: ${parsed.command}`);
  }
  if (!existsSync(parsed.command)) {
    output.log(`[FAIL] Codex command executable does not exist: ${parsed.command}`);
    ok = false;
  }
  const launcherPath = parsed.args[0];
  if (!launcherPath || !existsSync(launcherPath)) {
    output.log(`[FAIL] security-audit launcher does not exist: ${launcherPath || '<missing>'}`);
    ok = false;
  }
  if (parsed.args[1] !== 'mcp' || parsed.args.length !== 2) {
    output.log(`[FAIL] Expected launcher args [<bin/cli.js>, "mcp"], got ${JSON.stringify(parsed.args)}`);
    ok = false;
  }
  if (!ok) return false;

  try {
    const smoke = await runDirectMcpSmoke({ command: parsed.command, args: parsed.args, cwd, env });
    output.log('[OK] MCP initialize');
    output.log(`[OK] MCP tools/list: ${smoke.toolNames.length} tools`);
    return true;
  } catch (error) {
    output.log(`[FAIL] Direct MCP protocol smoke test: ${(error as Error).message}`);
    return false;
  }
}
