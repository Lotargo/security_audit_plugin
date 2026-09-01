import { spawn, execSync } from 'node:child_process';
import * as http from 'node:http';

export interface DockerRunnerOptions {
  containerName?: string;
  imageName?: string;
  hostPort?: number;
  workspacePath?: string;
  hostPubkeyHex?: string;
  memoryLimit?: string;
  pidsLimit?: number;
}

/**
 * DockerRunner manages the lifecycle of the isolated security sandbox container.
 */
export class DockerRunner {
  private containerName: string;
  private imageName: string;
  private hostPort: number;
  private workspacePath: string;
  private hostPubkeyHex?: string;
  private memoryLimit: string;
  private pidsLimit: number;

  constructor(options: DockerRunnerOptions = {}) {
    this.containerName = options.containerName || 'security-audit-sandbox';
    this.imageName = options.imageName || 'security-audit-sandbox:latest';
    this.hostPort = options.hostPort || 9999;
    this.workspacePath = options.workspacePath || process.cwd();
    this.hostPubkeyHex = options.hostPubkeyHex;
    this.memoryLimit = options.memoryLimit || '4g';
    this.pidsLimit = options.pidsLimit || 256;
  }

  /**
   * Checks if Docker daemon is running and reachable
   */
  public isDockerAvailable(): boolean {
    try {
      execSync('docker info --format "{{.ServerVersion}}"', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Checks if the sandbox container is currently running
   */
  public isRunning(): boolean {
    try {
      const out = execSync(`docker ps --filter "name=${this.containerName}" --format "{{.Names}}"`, {
        stdio: 'pipe',
      })
        .toString()
        .trim();
      return out.includes(this.containerName);
    } catch {
      return false;
    }
  }

  /**
   * Starts the sandbox container if not already active
   */
  public async ensureRunning(hostPubkeyHex?: string): Promise<void> {
    if (hostPubkeyHex) {
      this.hostPubkeyHex = hostPubkeyHex;
    }

    if (this.isRunning()) {
      const healthy = await this.checkHealth(1000);
      if (healthy) return;
    }

    // Clean up any stale or exited container
    this.stop();

    // Spawn docker container
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
    ];

    if (this.hostPubkeyHex) {
      args.push('-e', `HOST_PUBKEY_HEX=${this.hostPubkeyHex}`);
    }

    args.push(this.imageName);

    try {
      execSync(`docker ${args.join(' ')}`, { stdio: 'pipe' });
    } catch (err: any) {
      throw new Error(`Failed to start Docker sandbox container: ${err.message}`);
    }

    // Wait for health check
    const isUp = await this.waitForHealth(10000);
    if (!isUp) {
      throw new Error(`Sandbox container started but health check failed at http://127.0.0.1:${this.hostPort}`);
    }
  }

  /**
   * Performs an immediate Hard Reset: destroys compromised container and spawns clean image
   */
  public async hardReset(hostPubkeyHex?: string): Promise<void> {
    this.stop();
    await this.ensureRunning(hostPubkeyHex);
  }

  /**
   * Stops and removes the sandbox container
   */
  public stop(): void {
    try {
      execSync(`docker rm -f ${this.containerName}`, { stdio: 'pipe' });
    } catch {
      // Ignore if container did not exist
    }
  }

  /**
   * Single health check probe to sandbox-daemon
   */
  public checkHealth(timeoutMs: number = 1000): Promise<boolean> {
    return new Promise((resolve) => {
      const req = http.get(
        {
          host: '127.0.0.1',
          port: this.hostPort,
          path: '/isolation_status',
          timeout: timeoutMs,
        },
        (res) => {
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

  /**
   * Polls health check until healthy or timeout
   */
  public async waitForHealth(timeoutMs: number = 10000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const healthy = await this.checkHealth(800);
      if (healthy) return true;
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  }
}
