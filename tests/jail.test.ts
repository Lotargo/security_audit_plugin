import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { JailGuard, JailSecurityError } from '../src/mcp/security/jail.js';

describe('JailGuard Path Traversal Protection', () => {
  const workspaceRoot = path.resolve(process.cwd());
  const jail = new JailGuard(workspaceRoot);

  it('allows valid relative paths within workspace', () => {
    const safe = jail.resolveSafePath('reports/audit-report.sarif');
    expect(safe).toBe(path.resolve(workspaceRoot, 'reports/audit-report.sarif'));
  });

  it('allows valid nested subdirectories', () => {
    const safe = jail.resolveSafePath('src/mcp/tools/index.ts');
    expect(safe).toBe(path.resolve(workspaceRoot, 'src/mcp/tools/index.ts'));
  });

  it('rejects directory traversal using ../ escaping workspace', () => {
    expect(() => {
      jail.resolveSafePath('../../etc/passwd');
    }).toThrow(JailSecurityError);

    expect(() => {
      jail.resolveSafePath('../.ssh/id_rsa');
    }).toThrow(JailSecurityError);
  });

  it('rejects absolute paths outside workspace', () => {
    expect(() => {
      jail.resolveSafePath('C:\\Windows\\System32\\cmd.exe');
    }).toThrow(JailSecurityError);
  });

  it('rejects null byte injection', () => {
    expect(() => {
      jail.resolveSafePath('reports/report.sarif\0/../../secret');
    }).toThrow(JailSecurityError);

    expect(() => {
      jail.resolveSafePath('reports/report.sarif%00.png');
    }).toThrow(JailSecurityError);
  });

  it('rejects URL schemes in filesystem path', () => {
    expect(() => {
      jail.resolveSafePath('file:///etc/shadow');
    }).toThrow(JailSecurityError);
  });

  it('converts resolved path to relative posix format', () => {
    const rel = jail.toRelativePosix('reports/audit.sarif');
    expect(rel).toBe('reports/audit.sarif');
  });
});
