import { execFileSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

function getPackFileList(): string[] {
  // npm pack --dry-run --json prints [{ ..., files: [{ path }] }] without creating tarball.
  // Windows needs shell:true / npm.cmd resolution.
  const out = execFileSync('npm pack --dry-run --json', { encoding: 'utf8', shell: true });
  const parsed = JSON.parse(out) as Array<{ files?: Array<{ path?: string }>; path?: string; filename?: string }>;
  const first = parsed[0] as any;
  if (Array.isArray(first?.files)) {
    return (first.files as Array<{ path?: string }>).map((e) => (e.path ?? '').replace(/\\/g, '/'));
  }
  return parsed.map((e) => ((e as any).path ?? (e as any).filename ?? '').replace(/\\/g, '/'));
}

describe('npm packaging regression', () => {
  it('includes runtime assets required to start the sandbox (seccomp, stealth, tor, entrypoint)', () => {
    const files = getPackFileList();
    expect(files.length).toBeGreaterThan(0);

    const required = [
      'sandbox_runtime/seccomp/evolve-bwrap.json',
      'sandbox_runtime/Dockerfile',
      'sandbox_runtime/entrypoint.sh',
      'sandbox_runtime/stealth/browser_launcher.js',
      'sandbox_runtime/stealth/browser_guard.js',
      'sandbox_runtime/tor/torrc',
      'ROADMAP.md',
    ];
    for (const need of required) {
      expect(files.some((f) => f === need || f.endsWith('/' + need) || f.includes(need))).toBe(true);
    }
  });

  it('findSandboxSeccompProfile resolves inside the packed file list', () => {
    const files = getPackFileList();
    expect(files.some((f) => f.includes('sandbox_runtime/seccomp/evolve-bwrap.json'))).toBe(true);
    // And on-disk checkout still has it (fail-closed runner depends on it).
    const onDisk = path.resolve(process.cwd(), 'sandbox_runtime/seccomp/evolve-bwrap.json');
    expect(fs.existsSync(onDisk)).toBe(true);
  });
});
