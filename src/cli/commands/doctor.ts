import * as net from 'node:net';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { green, red, yellow, bold, cyan, gray } from 'colorette';

function checkPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => {
      server.close(() => resolve(true));
    });
    server.listen(port, '127.0.0.1');
  });
}

export interface DoctorOptions {
  codex?: boolean;
}

export async function runDoctor(options: DoctorOptions = {}): Promise<boolean> {
  console.log(bold(cyan('\n=== Security Audit Plugin Doctor: System Diagnostics ===\n'));
  let allHealthy = true;

  const nodeVersion = process.version;
  const major = parseInt(nodeVersion.replace('v', '').split('.')[0], 10);
  if (major >= 20) {
    console.log(`${green('✔')} Node.js Runtime: ${bold(nodeVersion)} (Supported)`);
  } else {
    console.log(`${red('✖')} Node.js Runtime: ${bold(nodeVersion)} (Requires >= v20.0.0)`);
    allHealthy = false;
  }

  try {
    const dockerVersion = execSync('docker version --format "{{.Server.Version}}"', { stdio: 'pipe' })
      .toString()
      .trim();
    console.log(`${green('✔')} Docker Daemon: ${bold(`v${dockerVersion}`)} (Active & Reachable)`);
  } catch {
    console.log(`${red('✖')} Docker Daemon: ${red('Not running or inaccessible')}`);
    console.log(gray('  Recommendation: Start Docker Desktop / dockerd service.'));
    allHealthy = false;
  }

  try {
    const imgOut = execSync('docker images security-audit-sandbox --format "{{.Repository}}:{{.Tag}}"', {
      stdio: 'pipe',
    })
      .toString()
      .trim();
    if (imgOut.includes('security-audit-sandbox')) {
      console.log(`${green('✔')} Sandbox Docker Image: ${bold(imgOut)} (Available)`);
    } else {
      console.log(`${yellow('⚠')} Sandbox Docker Image: ${yellow('security-audit-sandbox:latest not built yet')}`);
      console.log(gray('  Recommendation: Run `docker build -t security-audit-sandbox:latest sandbox_runtime/`'));
    }
  } catch {
    console.log(`${yellow('⚠')} Sandbox Docker Image: Unable to inspect docker images`);
  }

  const ports = [
    { port: 9999, desc: 'Sandbox HTTP Daemon' },
    { port: 9050, desc: 'Tor SOCKS5 In-Container Proxy' },
    { port: 9051, desc: 'Tor Control Port' },
  ];

  for (const p of ports) {
    const isFree = await checkPortFree(p.port);
    if (isFree) {
      console.log(`${green('✔')} Port ${p.port} (${p.desc}): Available`);
    } else {
      console.log(`${yellow('⚠')} Port ${p.port} (${p.desc}): Currently in use`);
    }
  }

  const skillsDir = path.resolve(process.cwd(), 'skills');
  if (fs.existsSync(skillsDir)) {
    const skillDirs = fs.readdirSync(skillsDir).filter((d) => fs.statSync(path.join(skillsDir, d)).isDirectory());
    if (skillDirs.length === 19) {
      console.log(`${green('✔')} Skills Ecosystem: ${bold(`${skillDirs.length} / 19 Skills`)} found and verified`);
    } else {
      console.log(`${yellow('⚠')} Skills Ecosystem: Found ${skillDirs.length} skills (Expected 19)`);
    }
  } else {
    console.log(`${red('✖')} Skills Ecosystem: Directory "skills/" not found at ${skillsDir}`);
    allHealthy = false;
  }

  if (options.codex) {
    console.log(bold(cyan('\n--- Codex MCP Registration & Protocol Smoke ---\n')));
    const { runCodexDoctor } = await import('../integration/client_diagnostics.js');
    const codexOk = await runCodexDoctor();
    if (!codexOk) allHealthy = false;
  }

  console.log('\n--------------------------------------------------------');
  if (allHealthy) {
    console.log(bold(green('Status: All requested requirements are SATISFIED. System is ready.')));
  } else {
    console.log(bold(yellow('Status: Some dependencies or integrations need attention.'));
  }
  console.log('--------------------------------------------------------\n');

  return allHealthy;
}
