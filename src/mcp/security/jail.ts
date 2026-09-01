import * as path from 'node:path';
import * as fs from 'node:fs';

export class JailSecurityError extends Error {
  constructor(message: string) {
    super(`JailSecurityViolation: ${message}`);
    this.name = 'JailSecurityError';
  }
}

/**
 * JailGuard enforces workspace isolation and prevents Path Traversal attacks.
 */
export class JailGuard {
  private workspaceRoot: string;

  constructor(workspaceRoot: string = process.cwd()) {
    this.workspaceRoot = path.resolve(workspaceRoot);
  }

  /**
   * Returns normalized absolute workspace root
   */
  public getWorkspaceRoot(): string {
    return this.workspaceRoot;
  }

  /**
   * Safely resolves a requested relative or absolute path against workspaceRoot.
   * Throws JailSecurityError if target escapes the workspace directory.
   */
  public resolveSafePath(userPath: string): string {
    if (!userPath || typeof userPath !== 'string') {
      throw new JailSecurityError('Path must be a non-empty string');
    }

    // Check for null byte injection
    if (userPath.includes('\0') || userPath.includes('%00')) {
      throw new JailSecurityError('Null byte injection detected in path');
    }

    // Normalize slashes
    const normalizedInput = userPath.replace(/\\/g, '/');

    // Disallow suspicious protocols or URL patterns
    if (
      normalizedInput.startsWith('file://') ||
      normalizedInput.startsWith('http://') ||
      normalizedInput.startsWith('https://')
    ) {
      throw new JailSecurityError('URL schemes are not allowed in filesystem paths');
    }

    // Reject UNC paths (//server/share or \\server\share)
    if (/^[/\\]{2}/.test(userPath)) {
      throw new JailSecurityError(`UNC network path forbidden: "${userPath}"`);
    }

    // Check Windows drive letter paths across all platforms (e.g. C:\Windows or C:/Windows)
    if (/^[a-zA-Z]:[/\\]/.test(userPath)) {
      if (process.platform !== 'win32') {
        throw new JailSecurityError(
          `Windows absolute path forbidden on POSIX: "${userPath}" resolves outside workspace root "${this.workspaceRoot}"`
        );
      }
    }

    // Resolve path relative to workspaceRoot
    const resolvedPath = path.resolve(this.workspaceRoot, userPath);

    // Verify resolved path starts with workspaceRoot
    const relative = path.relative(this.workspaceRoot, resolvedPath);
    const isEscaping = relative.startsWith('..') || path.isAbsolute(relative);

    if (isEscaping) {
      throw new JailSecurityError(
        `Path traversal forbidden: "${userPath}" resolves outside workspace root "${this.workspaceRoot}"`
      );
    }

    // If file/directory exists, verify realpath to prevent symlink traversal
    if (fs.existsSync(resolvedPath)) {
      try {
        const real = fs.realpathSync(resolvedPath);
        const realRelative = path.relative(this.workspaceRoot, real);
        if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
          throw new JailSecurityError(
            `Symlink traversal forbidden: "${userPath}" points to "${real}" outside workspace root`
          );
        }
      } catch (err: any) {
        if (err instanceof JailSecurityError) throw err;
      }
    }

    return resolvedPath;
  }

  /**
   * Converts an absolute path inside workspace to a relative posix path
   */
  public toRelativePosix(targetPath: string): string {
    const safePath = this.resolveSafePath(targetPath);
    const rel = path.relative(this.workspaceRoot, safePath);
    return rel.replace(/\\/g, '/');
  }
}
