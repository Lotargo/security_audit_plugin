import { Command } from 'commander';
import { createMcpServer } from '../mcp/server.js';
import { runDoctor } from './commands/doctor.js';
import { runInstallSkills } from './commands/install_skills.js';
import { runUninstallSkills } from './commands/uninstall_skills.js';
import {
  startSandboxCmd,
  stopSandboxCmd,
  resetSandboxCmd,
  pullSandboxCmd,
  buildSandboxCmd,
} from './commands/sandbox_cmd.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('security-audit')
    .description('Security Audit Plugin: Isolated Docker Sandbox, Rust Kernel, Stealth Browser, Tor & 19 AgentSkills')
    .version('0.4.0');

  // 1. MCP Server
  program
    .command('mcp')
    .description('Launch MCP Server over STDIO for AI Agent integration (AGY, OpenCode, Codex, Claude, Cursor)')
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

  // 3. Install Skills (with install / install-skills aliases)
  program
    .command('install')
    .alias('install-skills')
    .description('Install standardized skills into the target agent environment (AGY, Claude, OpenCode, local)')
    .option(
      '-t, --target <target>',
      'Target platform: "agy", "opencode", "claude", "local-agents", "all", or "custom"',
      'local-agents'
    )
    .option('-s, --skills <skills>', 'Comma-separated skill names or "all" (default: all)')
    .option('-p, --path <path>', 'Custom directory path (used when target is "custom")')
    .option('--mcp', 'Print MCP server configuration snippet for target environment')
    .option('--docker', 'Pre-warm / pull the sandbox Docker image during installation', false)
    .action(async (options) => {
      try {
        await runInstallSkills({
          target: options.target,
          path: options.path,
          skills: options.skills,
          mcp: options.mcp,
          docker: options.docker,
        });
      } catch (err: any) {
        console.error(`Error installing skills: ${err.message}`);
        process.exit(1);
      }
    });

  // 4. Uninstall Skills (with uninstall / uninstall-skills aliases)
  program
    .command('uninstall')
    .alias('uninstall-skills')
    .description('Uninstall skills from target agent environment')
    .option(
      '-t, --target <target>',
      'Target platform: "agy", "opencode", "claude", "local-agents", "all", or "custom"',
      'local-agents'
    )
    .option('-s, --skills <skills>', 'Comma-separated skill names to remove or "all" (default: all)')
    .option('-p, --path <path>', 'Custom directory path (used when target is "custom")')
    .option('--mcp', 'Print instructions for removing MCP server entry')
    .action(async (options) => {
      try {
        await runUninstallSkills({
          target: options.target,
          path: options.path,
          skills: options.skills,
          mcp: options.mcp,
        });
      } catch (err: any) {
        console.error(`Error uninstalling skills: ${err.message}`);
        process.exit(1);
      }
    });

  // 5. Init / Setup Wizard
  program
    .command('init')
    .description('Interactive setup and installation for AI Agent environments')
    .option('-t, --target <target>', 'Target platform', 'local-agents')
    .option('-s, --skills <skills>', 'Comma-separated skill names or "all"', 'all')
    .option('--mcp', 'Include MCP configuration snippet', true)
    .option('--docker', 'Pre-warm / pull the sandbox Docker image during setup', true)
    .action(async (options) => {
      console.log('\n--- Initializing Security Audit Plugin Setup ---\n');
      const doctorOk = await runDoctor();
      if (!doctorOk) {
        console.warn('\n[Warning] Some system checks failed. Continuing with skill installation...\n');
      }
      await runInstallSkills({
        target: options.target,
        skills: options.skills,
        mcp: options.mcp,
        docker: options.docker,
      });
    });

  // 6. Sandbox Lifecycle
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

  program
    .command('pull-sandbox')
    .description('Pull pre-built sandbox image from public registry (GHCR)')
    .option('-i, --image <name>', 'Registry image name')
    .action(pullSandboxCmd);

  program
    .command('build-sandbox')
    .description('Build sandbox container image locally from bundled sandbox_runtime')
    .option('-p, --path <path>', 'Custom path to sandbox_runtime directory')
    .action(buildSandboxCmd);

  return program;
}
