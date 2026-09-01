import { execSync } from 'node:child_process';
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
  memoryLimit?: string;
  pidsLimit?: number;
}

/**
 * Finds the bundled sandbox_runtime directory inside the installed package or development workspace
 */
export function findSandboxRuntimeDir(): string | null {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));

  const candidates = [
    // 1. From dist/src/docker/ (installed npm package)
    path.resolve(currentDir, '../../../sandbox_runtime'),
    // 2. From src/docker/ (ts-node / dev / vitest)
    path.resolve(currentDir, '../../sandbox_runtime'),
    // 3. Fallback to process.cwd()
    path.resolve(process.cwd(), 'sandbox_runtime'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(path.join(candidate, 'Dockerfile'))) {
      return candidate;
    }
  }

  return null;
}

/**
 * DockerRunner manages the lifecycle of the isolated security sandbox container,
 * with automatic image pulling from GHCR and fallback build from bundled runtime sources.
 */
export class DockerRunner {
  private containerName: string;
  private imageName: string;
  private registryImage: string;
  private hostPort: number;
  private workspacePath: string;
  private hostPubkeyHex?: string;
  private memoryLimit: string;
  private pidsLimit: number;

  constructor(options: DockerRunnerOptions = {}) {
    this.containerName = options.containerName || 'security-audit-sandbox';
    this.imageName = options.imageName || DEFAULT_LOCAL_IMAGE;
    this.registryImage = options.registryImage || DEFAULT_REGISTRY_IMAGE;
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
   * Checks if a Docker image is present in local cache
   */
  public isImageAvailable(imageName?: string): boolean {
    const target = imageName || this.imageName;
    try {
      const out = execSync(`docker images -q "${target}"`, { stdio: 'pipe' }).toString().trim();
      if (out.length > 0) return true;

      // Also check if the registry image is present
      const regOut = execSync(`docker images -q "${this.registryImage}"`, { stdio: 'pipe' }).toString().trim();
      return regOut.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Pulls the pre-built sandbox image from public registry (GHCR / Docker Hub)
   */
  public pullImage(registryImage?: string): boolean {
    const target = registryImage || this.registryImage;
    console.error(`[*] Pulling sandbox image from registry: ${target}...`);
    try {
      execSync(`docker pull ${target}`, { stdio: 'inherit' });
      if (target !== this.imageName) {
        execSync(`docker tag ${target} ${this.imageName}`, { stdio: 'pipe' });
      }
      return true;
    } catch (err: any) {
      console.error(`[!] Failed to pull image from ${target}: ${err.message}`);
      return false;
    }
  }

  /**
   * Builds the sandbox image locally from the bundled sandbox_runtime directory
   */
  public buildImage(customRuntimePath?: string): boolean {
    const runtimeDir = customRuntimePath || findSandboxRuntimeDir();
    if (!runtimeDir) {
      console.error('[!] Could not locate sandbox_runtime directory with Dockerfile.');
      return false;
    }

    console.error(`[*] Building sandbox container locally from: ${runtimeDir}...`);
    try {
      execSync(`docker build -t ${this.imageName} "${runtimeDir}"`, { stdio: 'inherit' });
      return true;
    } catch (err: any) {
      console.error(`[!] Docker build failed: ${err.message}`);
      return false;
    }
  }

  /**
   * Ensures the sandbox image is available locally (checks cache -> pulls -> builds fallback)
   */
  public async ensureImageAvailable(): Promise<void> {
    if (this.isImageAvailable()) {
      return;
    }

    console.error(`[*] Sandbox Docker image '${this.imageName}' not found locally.`);

    // 1. Primary path: Pull from public container registry (GHCR)
    const pulled = this.pullImage();
    if (pulled) {
      console.error(`[✔] Successfully downloaded sandbox image from ${this.registryImage}`);
      return;
    }

    // 2. Fallback path: Build locally from bundled source
    console.error(`[*] Registry pull failed or offline. Attempting local Docker build fallback...`);
    const built = this.buildImage();
    if (built) {
      console.error(`[✔] Successfully built sandbox image locally: ${this.imageName}`);
      return;
    }

    throw new Error(
      `Sandbox Docker image '${this.imageName}' is unavailable. Automatic registry pull and local build both failed. Ensure Docker is running and Internet access is available.`
    );
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

    // Ensure Docker daemon is up
    if (!this.isDockerAvailable()) {
      throw new Error(
        'Docker daemon is not running or inaccessible. Please start Docker Desktop or dockerd to run the security audit sandbox.'
      );
    }

    // Ensure image is downloaded or built
    await this.ensureImageAvailable();

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
