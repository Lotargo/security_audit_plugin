import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { RatchetBridge } from './security/ratchet_bridge.js';
import { JailGuard } from './security/jail.js';
import { SecretRedactor } from './security/redaction.js';
import { DockerRunner } from '../docker/runner.js';

export interface ScopeOptions {
  mode: 'local' | 'remote' | 'hybrid';
  targets?: string[];
  proxy?: string;
  ca_cert_b64?: string;
  arm_canaries?: boolean;
  allowed_cidrs?: string[];
  denied_cidrs?: string[];
}

export interface HttpProbeOptions {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  proxy?: string;
}

export interface BrowserAuditOptions {
  url: string;
  auth_headers?: Record<string, string>;
  cookies?: any[];
  proxy?: string;
  bypass_turnstile?: boolean;
  generate_decoy_noise?: boolean;
  spoof_headers?: Record<string, string>;
}

export interface BundleExtractOptions {
  url: string;
  proxy?: string;
  out_dir?: string;
}

/**
 * SandboxBridge provides high-level typed RPC communication
 * between the Host MCP Server and the Rust Sandbox Daemon.
 */
export class SandboxBridge {
  private ratchet: RatchetBridge;
  private jail: JailGuard;
  private docker: DockerRunner;
  private hostPort: number;
  private baseUrl: string;

  constructor(options?: {
    workspaceRoot?: string;
    hostPort?: number;
    customPrivateKeyPem?: string;
  }) {
    const workspaceRoot = options?.workspaceRoot || process.cwd();
    this.hostPort = options?.hostPort || 9999;
    this.baseUrl = `http://127.0.0.1:${this.hostPort}`;

    this.ratchet = new RatchetBridge(options?.customPrivateKeyPem);
    this.jail = new JailGuard(workspaceRoot);
    this.docker = new DockerRunner({
      hostPort: this.hostPort,
      workspacePath: workspaceRoot,
      hostPubkeyHex: this.ratchet.getPublicKeyHex(),
    });
  }

  public getRatchet(): RatchetBridge {
    return this.ratchet;
  }

  public getJail(): JailGuard {
    return this.jail;
  }

  public getDocker(): DockerRunner {
    return this.docker;
  }

  /**
   * Dispatches signed HTTP request to sandbox daemon with transparent rolling retry on 401/403
   */
  public async request<T = any>(
    method: 'GET' | 'POST',
    apiPath: string,
    bodyObj?: any,
    retryCount: number = 1
  ): Promise<T> {
    const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
    const { headers, rawBody } = this.ratchet.signRequest(method, apiPath, bodyStr);

    const executeOnce = (): Promise<{ statusCode: number; data: string }> => {
      return new Promise((resolve, reject) => {
        const parsedUrl = new URL(this.baseUrl + apiPath);
        const req = http.request(
          {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port,
            path: parsedUrl.pathname + parsedUrl.search,
            method,
            headers: {
              ...headers,
              'content-length': rawBody.length.toString(),
            },
            timeout: 60000,
          },
          (res) => {
            let responseData = '';
            res.on('data', (chunk) => {
              responseData += chunk;
            });
            res.on('end', () => {
              resolve({ statusCode: res.statusCode || 500, data: responseData });
            });
          }
        );

        req.on('error', (err) => reject(new Error(`Sandbox daemon unreachable: ${err.message}`)));
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Sandbox request timed out'));
        });

        if (rawBody.length > 0) {
          req.write(rawBody);
        }
        req.end();
      });
    };

    try {
      const { statusCode, data } = await executeOnce();

      if (statusCode >= 200 && statusCode < 300) {
        try {
          return JSON.parse(data) as T;
        } catch {
          return data as any;
        }
      }

      // If epoch drifted or authentication failed (401/403), perform transparent rolling retry with fresh epoch
      if ((statusCode === 401 || statusCode === 403) && retryCount > 0) {
        // Sleep 150ms and retry with fresh epoch
        await new Promise((r) => setTimeout(r, 150));
        return this.request<T>(method, apiPath, bodyObj, retryCount - 1);
      }

      try {
        const errObj = JSON.parse(data);
        throw new Error(errObj.error || `HTTP ${statusCode}: ${data}`);
      } catch (parseErr: any) {
        if (parseErr.message && !parseErr.message.startsWith('HTTP')) {
          throw parseErr;
        }
        throw new Error(`HTTP ${statusCode}: ${data}`);
      }
    } catch (err: any) {
      if (retryCount > 0 && err.message && (err.message.includes('401') || err.message.includes('403'))) {
        await new Promise((r) => setTimeout(r, 150));
        return this.request<T>(method, apiPath, bodyObj, retryCount - 1);
      }
      throw err;
    }
  }

  /**
   * 1. Sets audit scope and applies nftables firewall rules
   */
  public async setScope(options: ScopeOptions): Promise<any> {
    const enableTor = options.proxy === 'tor' || options.proxy === 'socks5://127.0.0.1:9050';
    const payload = {
      mode: options.mode,
      allowed_hosts: options.targets || [],
      allowed_cidrs: options.allowed_cidrs || [],
      denied_cidrs: options.denied_cidrs || [],
      enable_tor: enableTor,
      upstream_proxy: options.proxy && !enableTor ? options.proxy : null,
    };

    const egressRes = await this.request('POST', '/provision_egress', payload);

    if (options.arm_canaries) {
      await this.armCanary();
    }

    return egressRes;
  }

  /**
   * 2. Triggers Tor circuit rotation (SIGNAL NEWNYM)
   */
  public async rotateTor(): Promise<{ status: string; message: string; exit_ip?: string }> {
    return this.request('POST', '/rotate_tor', {});
  }

  /**
   * 3. Executes command inside sandbox with watchdog & auto-truncation
   */
  public async exec(
    command: string,
    timeoutSecs: number = 60
  ): Promise<{ exit_code: number; stdout: string; stderr: string; truncated: boolean; log_path?: string }> {
    return this.request('POST', '/execute', {
      command,
      timeout_secs: timeoutSecs,
    });
  }

  /**
   * 4. Sends interactive input to active tmux session
   */
  public async interactiveInput(
    input: string,
    session: string = 'main'
  ): Promise<{ status: string; output: string }> {
    return this.request('POST', '/execute_tmux', {
      session,
      input,
    });
  }

  /**
   * 5. Starts long-running command in background tmux session
   */
  public async startBackground(
    command: string,
    session: string = 'background_scan'
  ): Promise<{ status: string; session: string; message: string }> {
    return this.request('POST', '/start_background', {
      command,
      session,
    });
  }

  /**
   * 6. Polls incremental logs from background session
   */
  public async pollLogs(
    session: string = 'background_scan'
  ): Promise<{ session: string; active: boolean; delta_logs: string }> {
    return this.request('GET', `/poll_logs?session=${encodeURIComponent(session)}`);
  }

  /**
   * 7. Runs stealth browser audit
   */
  public async browserAudit(options: BrowserAuditOptions): Promise<any> {
    const cleanHeaders = options.auth_headers ? SecretRedactor.redactHeaders(options.auth_headers) : {};
    const cmd = `node /sandbox/stealth/browser_launcher.js --url "${options.url}"` +
      (options.proxy ? ` --proxy "${options.proxy}"` : '') +
      (options.bypass_turnstile ? ` --turnstile` : '') +
      (options.generate_decoy_noise ? ` --decoy` : '');

    return this.exec(cmd, 120);
  }

  /**
   * 8. Extracts client JS bundles, source maps, and builds API endpoint map
   */
  public async bundleExtract(options: BundleExtractOptions): Promise<any> {
    const outDir = options.out_dir || '/workspace/extracted_bundles';
    const cmd = `node /sandbox/stealth/bundle_extractor.js --url "${options.url}" --out "${outDir}"` +
      (options.proxy ? ` --proxy "${options.proxy}"` : '');

    return this.exec(cmd, 180);
  }

  /**
   * 9. Sends HTTP probe with L7 IP Spoofing capabilities
   */
  public async httpProbe(options: HttpProbeOptions): Promise<any> {
    return this.request('POST', '/http_probe', {
      url: options.url,
      method: options.method || 'GET',
      headers: options.headers || {},
      body: options.body || '',
      proxy: options.proxy || null,
    });
  }

  /**
   * 10. Emergency Kill Switch (L2/L3 Network Blackout)
   */
  public async killSwitch(reason: string = 'Manual kill switch triggered'): Promise<any> {
    return this.request('POST', '/emergency_isolate', { reason });
  }

  /**
   * 11. Arms decoy canary honeytokens inside container
   */
  public async armCanary(tokenLabel: string = 'default_audit_canary'): Promise<any> {
    return this.request('POST', '/arm_canary', { token_label: tokenLabel });
  }

  /**
   * 12. Reads file in workspace with JailGuard protection
   */
  public fsRead(relPath: string): { path: string; content: string } {
    const safePath = this.jail.resolveSafePath(relPath);
    if (!fs.existsSync(safePath)) {
      throw new Error(`File not found: ${relPath}`);
    }
    const content = fs.readFileSync(safePath, 'utf-8');
    return {
      path: this.jail.toRelativePosix(safePath),
      content,
    };
  }

  /**
   * 13. Writes file in workspace with JailGuard protection
   */
  public fsWrite(relPath: string, content: string): { path: string; bytesWritten: number } {
    const safePath = this.jail.resolveSafePath(relPath);
    const dir = path.dirname(safePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(safePath, content, 'utf-8');
    return {
      path: this.jail.toRelativePosix(safePath),
      bytesWritten: Buffer.byteLength(content, 'utf-8'),
    };
  }

  /**
   * 14. Resets container to clean state
   */
  public async reset(fullCleanup: boolean = false): Promise<{ status: string; message: string }> {
    if (fullCleanup) {
      await this.docker.hardReset(this.ratchet.getPublicKeyHex());
    } else {
      await this.killSwitch('Reset called');
    }
    return {
      status: 'ok',
      message: 'Sandbox instance cleanly reset',
    };
  }
}
