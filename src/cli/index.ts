import { Command } from 'commander';
import { createMcpServer } from '../mcp/server.js';
import { runDoctor } from './commands/doctor.js';
import { runInstallSkills } from './commands/install_skills.js';
import { startSandboxCmd, stopSandboxCmd, resetSandboxCmd } from './commands/sandbox_cmd.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('security-audit')
    .description('Security Audit Plugin: Isolated Docker Sandbox, Rust Kernel, Stealth Browser, Tor & 19 AgentSkills')
    .version('0.3.0');

  // 1. MCP Server
  program
    .command('mcp')
    .description('Launch MCP Server over STDIO for AI Agent integration (AGY, OpenCode, Codex, Claude)')
    .option('-w, --workspace <path>', 'Workspace directory path', process.cwd())
    .option('-p, --port <port>', 'Sandbox daemon port', '9999')
    .action(async (options) => {
      const serverInst = await createMcpServer({
        workspaceRoot: options.workspace,
        hostPort: parseInt(options.port, 10),
      });
      await serverInst.start();
    });

  // 2. Doctor Diagnostics
  program
    .command('doctor')
    .description('Check system requirements (Docker, Tor, ports, skills ecosystem)')
    .action(async () => {
      const ok = await runDoctor();
      process.exit(ok ? 0 : 1);
    });

  // 3. Install Skills
  program
    .command('install-skills')
    .description('Install 19 standardized skills into the target agent environment')
    .option(
      '-t, --target <target>',
      'Target platform: "agy", "opencode", "claude", "local-agents", or "custom"',
      'local-agents'
    )
    .option('-p, --path <path>', 'Custom directory path (used when target is "custom")')
    .action(async (options) => {
      try {
        await runInstallSkills({ target: options.target, path: options.path });
      } catch (err: any) {
        console.error(`Error installing skills: ${err.message}`);
        process.exit(1);
      }
    });

  // 4. Sandbox Lifecycle
  program
    .command('start-sandbox')
    .description('Start the isolated Docker sandbox container in background')
    .action(startSandboxCmd);

  program
    .command('stop-sandbox')
    .description('Stop and remove the Docker sandbox container')
    .action(stopSandboxCmd);

  program
    .command('reset-sandbox')
    .description('Emergency Hard Reset: destroy and recreate a pristine sandbox container')
    .action(resetSandboxCmd);

  return program;
}
