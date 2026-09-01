import { execFileSync } from 'node:child_process';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_REGISTRY_IMAGE = 'ghcr.io/lotargo/security-audit-sandbox:latest';
export const DEFAULT_LOCAL_IMAGE = 'security-audit-sandbox:latest';

export interface DockerRunnerOptions {
  containerName?: string;
  imageName?: string;
  registryImage?: string;
  hostPort?: number;
  workspacePath?: string;
  hostPubkeyHex?: string;
  sessionKeyHex?: string;
  memoryLimit?: string;
  pidsLimit?: number;
}

export function findSandboxRuntimeDir(): string | null {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(currentDir, '../../../sandbox_runtime'),
    path.resolve(currentDir, '../../sandbox_runtime'),
    path.resolve(process.cwd(), 'sandbox_runtime'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'Dockerfile'))) {
      return candidate;
    }
  }
  return null;
}

export class DockerRunner {
  private containerName: string;
  private imageName: string;
  private registryImage: string;
  private hostPort: number;
  private workspacePath: string;
  private hostPubkeyHex?: string;
  private sessionKeyHex?: string;
  private memoryLimit: string;
  private pidsLimit: number;

  constructor(options: DockerRunnerOptions = {}) {
    this.containerName = options.containerName || 'security-audit-sandbox';
    this.imageName = options.imageName || DEFAULT_LOCAL_IMAGE;
    this.registryImage = options.registryImage || DEFAULT_REGISTRY_IMAGE;
    this.hostPort = options.hostPort || 9999;
    this.workspacePath = options.workspacePath || process.cwd();
    this.hostPubkeyHex = options.hostPubkeyHex;
    this.sessionKeyHex = options.sessionKeyHex;
    this.memoryLimit = options.memoryLimit || '4g';
    this.pidsLimit = options.pidsLimit || 256;
  }

  private docker(args: string[], inherit = false): Buffer {
    return execFileSync('docker', args, {
      stdio: inherit ? 'inherit' : 'pipe',
      maxBuffer: 16 * 1024 * 1024,
    }) as Buffer;
  }

  public isDockerAvailable(): boolean {
    try {
      this.docker(['info', '--format', '{{.ServerVersion}}']);
      return true;
    } catch {
      return false;
    }
  }

  public isRunning(): boolean {
    try {
      const out = this.docker([
        'ps',
        '--filter',
        `name=^/${this.containerName}$`,
        '--format',
        '{{.Names}}',
      ])
        .toString()
        .trim();
      return out === this.containerName;
    } catch {
      return false;
    }
  }

  public isImageAvailable(imageName?: string): boolean {
    const target = imageName || this.imageName;
    try {
      if (this.docker(['images', '-q', target]).toString().trim()) return true;
      return Boolean(this.docker(['images', '-q', this.registryImage]).toString().trim());
    } catch {
      return false;
    }
  }

  public pullImage(registryImage?: string): boolean {
    const target = registryImage || this.registryImage;
    console.error(`[*] Pulling sandbox image from registry: ${target}...`);
    try {
      this.docker(['pull', target], true);
      if (target !== this.imageName) {
        this.docker(['tag', target, this.imageName]);
      }
      return true;
    } catch (err: any) {
      console.error(`[!] Failed to pull image from ${target}: ${err.message}`);
      return false;
    }
  }

  public buildImage(customRuntimePath?: string): boolean {
    const runtimeDir = customRuntimePath || findSandboxRuntimeDir();
    if (!runtimeDir) {
      console.error('[!] Could not locate sandbox_runtime directory with Dockerfile.');
      return false;
    }

    console.error(`[*] Building sandbox container locally from: ${runtimeDir}...`);
    try {
      this.docker(['build', '-t', this.imageName, runtimeDir], true);
      return true;
    } catch (err: any) {
      console.error(`[!] Docker build failed: ${err.message}`);
      return false;
    }
  }

  public async ensureImageAvailable(): Promise<void> {
    if (this.isImageAvailable()) return;

    console.error(`[*] Sandbox Docker image '${this.imageName}' not found locally.`);
    if (this.pullImage()) {
      console.error(`[✔] Successfully downloaded sandbox image from ${this.registryImage}`);
      return;
    }

    console.error('[*] Registry pull failed or offline. Attempting local Docker build fallback...');
    if (this.buildImage()) {
      console.error(`[✔] Successfully built sandbox image locally: ${this.imageName}`);
      return;
    }

    throw new Error(
      `Sandbox Docker image '${this.imageName}' is unavailable. Registry pull and local build both failed.`
    );
  }

  private hasMatchingTrustMaterial(): boolean {
    if (!this.hostPubkeyHex || !this.sessionKeyHex || !this.isRunning()) return false;
    try {
      const envDump = this.docker([
        'inspect',
        '--format',
        '{{range .Config.Env}}{{println .}}{{end}}',
        this.containerName,
      ]).toString();
      return (
        envDump.includes(`HOST_PUBKEY_HEX=${this.hostPubkeyHex}`) &&
        envDump.includes(`BRIDGE_SESSION_KEY_HEX=${this.sessionKeyHex}`)
      );
    } catch {
      return false;
    }
  }

  public async ensureRunning(hostPubkeyHex?: string, sessionKeyHex?: string): Promise<void> {
    if (hostPubkeyHex) this.hostPubkeyHex = hostPubkeyHex;
    if (sessionKeyHex) this.sessionKeyHex = sessionKeyHex;

    if (!this.hostPubkeyHex || !this.sessionKeyHex) {
      throw new Error(
        'Authenticated sandbox startup requires both HOST_PUBKEY_HEX and BRIDGE_SESSION_KEY_HEX'
      );
    }

    if (this.isRunning()) {
      const healthy = await this.checkHealth(1000);
      if (healthy && this.hasMatchingTrustMaterial()) return;
      // Never reuse a container that was bootstrapped by another MCP session/keypair.
      this.stop();
    }

    if (!this.isDockerAvailable()) {
      throw new Error('Docker daemon is not running or inaccessible.');
    }

    await this.ensureImageAvailable();
    this.stop();

    const args = [
      'run',
      '-d',
      '--name',
      this.containerName,
      '--cap-add=NET_ADMIN',
      '--security-opt=no-new-privileges:true',
      `--pids-limit=${this.pidsLimit}`,
      `--memory=${this.memoryLimit}`,
      '-p',
      `127.0.0.1:${this.hostPort}:9999`,
      '-v',
      `${this.workspacePath}:/workspace:rw`,
      '-e',
      `HOST_PUBKEY_HEX=${this.hostPubkeyHex}`,
      '-e',
      `BRIDGE_SESSION_KEY_HEX=${this.sessionKeyHex}`,
      this.imageName,
    ];

    try {
      this.docker(args);
    } catch (err: any) {
      throw new Error(`Failed to start Docker sandbox container: ${err.message}`);
    }

    if (!(await this.waitForHealth(15000))) {
      this.stop();
      throw new Error(`Sandbox container started but /health failed at 127.0.0.1:${this.hostPort}`);
    }
  }

  public async hardReset(hostPubkeyHex?: string, sessionKeyHex?: string): Promise<void> {
    this.stop();
    await this.ensureRunning(hostPubkeyHex, sessionKeyHex);
  }

  public stop(): void {
    try {
      this.docker(['rm', '-f', this.containerName]);
    } catch {
      // Container did not exist.
    }
  }

  public checkHealth(timeoutMs = 1000): Promise<boolean> {
    return new Promise((resolve) => {
      const req = http.get(
        {
          host: '127.0.0.1',
          port: this.hostPort,
          path: '/health',
          timeout: timeoutMs,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode === 200);
        }
      );
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
    });
  }

  public async waitForHealth(timeoutMs = 10000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (await this.checkHealth(800)) return true;
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  }
}
