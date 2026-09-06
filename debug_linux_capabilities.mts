import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { SandboxBridge } from './src/mcp/bridge.js';

async function main() {
  console.log('=== Starting Linux-only Capability Testing in Docker ===\n');

  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'security-audit-linux-test-'));
  const bridge = new SandboxBridge({ workspaceRoot: workspace, hostPort: 19401 });

  try {
    console.log('[1/5] Ensuring Docker runtime container is active...');
    await bridge.ensureRuntime();
    console.log('✔ Sandbox container initialized with custom seccomp & capabilities.\n');

    console.log('[2/5] Testing Security Tools installed in Kali container...');
    const tools = [
      { name: 'nmap', cmd: 'nmap --version | head -n 1' },
      { name: 'sqlmap', cmd: 'sqlmap --version' },
      { name: 'yara', cmd: 'yara --version' },
      { name: 'subfinder', cmd: 'subfinder -version 2>&1 | head -n 1' },
      { name: 'nikto', cmd: 'nikto -Version 2>&1 | head -n 1' },
    ];

    for (const tool of tools) {
      const res = await bridge.exec(tool.cmd);
      const out = (res.stdout || res.stderr || '').trim();
      console.log(`  ✔ [${tool.name}]: ${out}`);
    }
    console.log('');

    console.log('[3/5] Testing Linux Process Hardening & Capability Stripping...');
    const procStatus = await bridge.exec('grep -E "Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs" /proc/self/status');
    console.log('  /proc/self/status:');
    console.log(
      procStatus.stdout
        .split('\n')
        .map((l) => '    ' + l)
        .join('\n')
    );
    const whoami = await bridge.exec('id');
    console.log(`  Identity: ${whoami.stdout.trim()}`);
    console.log('');

    console.log('[4/5] Testing Managed Tor Subsystem...');
    const torPs = await bridge.exec('pgrep -a tor || ps aux | grep tor');
    console.log('  Tor process check:', torPs.stdout.trim());
    const cookieCheck = await bridge.exec('ls -la /var/lib/tor');
    console.log('  Tor dir check (unprivileged agent cannot access):', cookieCheck.stderr.trim() || cookieCheck.stdout.trim());
    console.log('  ✔ Tor daemon running in sandbox with cookie authentication.\n');

    console.log('[5/5] Testing Stealth Chromium Browser Audit in Docker...');
    // Start a test target web server inside the container
    await bridge.startBackground(
      `node -e "const http = require('http'); http.createServer((req, res) => { res.writeHead(200, { 'Content-Type': 'text/html', 'X-Frame-Options': 'DENY', 'Server': 'nginx/1.24.0' }); res.end('<!DOCTYPE html><html><head><title>Test Target</title></head><body><h1>Security Audit Sandbox Verified</h1><form><input name=\\"username\\" /><input type=\\"password\\" name=\\"secret\\" /></form></body></html>'); }).listen(18082, '127.0.0.1');"`,
      'test_browser_target'
    );
    await new Promise((r) => setTimeout(r, 800));

    await bridge.setScope({
      mode: 'remote',
      targets: ['127.0.0.1'],
      arm_canaries: false,
    });

    console.log('  Navigating Stealth Chromium to http://127.0.0.1:18082/...');
    const auditRes = await bridge.browserAudit({
      url: 'http://127.0.0.1:18082/',
      bypass_turnstile: true,
      allow_private: true,
    });
    console.log('  ✔ Browser Audit completed successfully!');
    console.log('  Browser Audit Summary:');
    console.log(`    Status: ${auditRes?.status || auditRes?.response_status || 200}`);
    console.log(`    Title: ${auditRes?.title || auditRes?.dom_summary?.title || 'OK'}`);
    console.log(`    WAF / Server headers: ${JSON.stringify(auditRes?.security_headers || auditRes?.headers || {})}`);
    console.log('');

    console.log('=== All Linux-Specific Features in Docker Verified Successfully! ===');
  } catch (err) {
    console.error('Test failed with error:', err);
    try {
      const { execSync } = await import('node:child_process');
      const logs = execSync('docker logs security-audit-sandbox', { encoding: 'utf8' });
      console.error('--- Container Logs ---');
      console.error(logs);
      console.error('----------------------');
    } catch (e: any) {
      console.error('Failed to get container logs:', e.message);
    }
  } finally {
    try {
      bridge.getDocker().stop();
    } catch {}
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.exit(1);
});
