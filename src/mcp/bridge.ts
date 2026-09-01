import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { RatchetBridge } from './security/ratchet_bridge.js';
import { JailGuard } from './security/jail.js';
import {
  isUrlInScope,
  normalizeCidrList,
  normalizeScopeHosts,
  resolveScopeTargets,
} from './security/scope_resolver.js';
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

export interface ExecResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  log_path?: string;
}

interface DaemonExecResult {
  output: string;
  exit_code: number;
  is_truncated: boolean;
  total_chars: number;
  log_file_path?: string | null;
}

interface ActiveNetworkScope {
  mode: 'local' | 'remote' | 'hybrid';
  targetHosts: string[];
  proxy: string | null;
}

const TOR_PROXY = 'socks5://127.0.0.1:9050';

export class SandboxBridge {
  private ratchet: RatchetBridge;
  private jail: JailGuard;
  private docker: DockerRunner;
  private hostPort: number;
  private baseUrl: string;
  private activeNetworkScope: ActiveNetworkScope = {
    mode: 'local',
    targetHosts: [],
    proxy: null,
  };

  constructor(options?: {
    workspaceRoot?: string;
    hostPort?: number;
    customPrivateKeyPem?: string;
    sessionKeyHex?: string;
  }) {
    const workspaceRoot = options?.workspaceRoot || process.cwd();
    this.hostPort = options?.hostPort || 9999;
    this.baseUrl = `http://127.0.0.1:${this.hostPort}`;

    this.ratchet = new RatchetBridge(options?.customPrivateKeyPem, options?.sessionKeyHex);
    this.jail = new JailGuard(workspaceRoot);
    this.docker = new DockerRunner({
      hostPort: this.hostPort,
      workspacePath: workspaceRoot,
      hostPubkeyHex: this.ratchet.getPublicKeyHex(),
      sessionKeyHex: this.ratchet.getSessionKeyHex(),
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

  public async ensureRuntime(): Promise<void> {
    await this.docker.ensureRunning(
      this.ratchet.getPublicKeyHex(),
      this.ratchet.getSessionKeyHex()
    );
  }

  public async request<T = any>(
    method: 'GET' | 'POST',
    apiPath: string,
    bodyObj?: any,
    retryCount: number = 1
  ): Promise<T> {
    const bodyStr = bodyObj === undefined ? '' : JSON.stringify(bodyObj);
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
            res.on('end', () => resolve({ statusCode: res.statusCode || 500, data: responseData }));
          }
        );

        req.on('error', (err) => reject(new Error(`Sandbox daemon unreachable: ${err.message}`)));
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Sandbox request timed out'));
        });
        if (rawBody.length > 0) req.write(rawBody);
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

      if ((statusCode === 401 || statusCode === 403) && retryCount > 0) {
        await new Promise((r) => setTimeout(r, 150));
        return this.request<T>(method, apiPath, bodyObj, retryCount - 1);
      }

      try {
        const errObj = JSON.parse(data);
        throw new Error(errObj.error || `HTTP ${statusCode}: ${data}`);
      } catch (parseErr: any) {
        if (parseErr.message && !parseErr.message.startsWith('HTTP')) throw parseErr;
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

  public async setScope(options: ScopeOptions): Promise<any> {
    if (options.ca_cert_b64) {
      throw new Error(
        'Custom CA injection is not implemented yet; refusing to silently ignore ca_cert_b64'
      );
    }

    const enableTor = options.proxy === 'tor' || options.proxy === TOR_PROXY;
    const proxyTarget = options.proxy && !enableTor ? options.proxy : undefined;
    const networkedMode = options.mode === 'remote' || options.mode === 'hybrid';

    if (proxyTarget) {
      throw new Error(
        'External upstream proxy containment is not implemented safely yet; use direct scoped egress or proxy="tor"'
      );
    }

    const resolvedTargets = networkedMode
      ? await resolveScopeTargets(options.targets || [])
      : [];
    const explicitAllowed = normalizeCidrList(options.allowed_cidrs || [], 'allowed CIDR');
    const allowedCidrs = [...new Set([...resolvedTargets, ...explicitAllowed])].sort();
    const deniedCidrs = options.denied_cidrs
      ? normalizeCidrList(options.denied_cidrs, 'denied CIDR')
      : undefined;
    const targetHosts = networkedMode ? normalizeScopeHosts(options.targets || []) : [];

    if (enableTor && targetHosts.length === 0) {
      throw new Error('Tor scope requires at least one explicit domain, URL, or single-IP target');
    }

    if (networkedMode && allowedCidrs.length === 0 && !enableTor) {
      throw new Error('Remote/hybrid scope requires at least one target or allowed CIDR');
    }

    const payload = {
      mode: options.mode,
      targets: options.targets || [],
      allowed_cidrs: allowedCidrs,
      denied_cidrs: deniedCidrs,
      tor_enabled: enableTor,
      proxy_enabled: false,
      proxy_target: null,
    };

    const egressRes = await this.request('POST', '/provision_egress', payload);
    this.activeNetworkScope = {
      mode: options.mode,
      targetHosts,
      proxy: enableTor ? TOR_PROXY : null,
    };

    if (options.arm_canaries) await this.armCanary();
    return egressRes;
  }

  private prepareManagedNetworkCall(url: string, requestedProxy?: string): {
    proxy: string | null;
    allowedHosts: string[];
  } {
    if (this.activeNetworkScope.mode === 'local') {
      throw new Error('Managed network calls require an explicit remote or hybrid scope');
    }

    const { targetHosts, proxy: scopedProxy } = this.activeNetworkScope;
    if (targetHosts.length > 0 && !isUrlInScope(url, targetHosts)) {
      throw new Error(`URL is outside the active audit scope: ${url}`);
    }

    let normalizedRequestedProxy: string | null = null;
    if (requestedProxy) {
      normalizedRequestedProxy = requestedProxy === 'tor' ? TOR_PROXY : requestedProxy;
      if (normalizedRequestedProxy !== scopedProxy) {
        throw new Error('Per-call proxy does not match the active sandbox scope');
      }
    }

    return {
      proxy: normalizedRequestedProxy || scopedProxy,
      allowedHosts: targetHosts,
    };
  }

  public async rotateTor(): Promise<{ status: string; message: string; exit_ip?: string }> {
    if (this.activeNetworkScope.proxy !== TOR_PROXY) {
      throw new Error('Tor rotation requires an active Tor-enabled scope');
    }
    return this.request('POST', '/rotate_tor', {});
  }

  public async exec(command: string, timeoutSecs: number = 60): Promise<ExecResult> {
    const raw = await this.request<DaemonExecResult>('POST', '/execute', {
      command,
      timeout_secs: timeoutSecs,
    });
    return {
      exit_code: raw.exit_code,
      stdout: raw.output || '',
      stderr: '',
      truncated: raw.is_truncated,
      log_path: raw.log_file_path || undefined,
    };
  }

  public async interactiveInput(
    input: string,
    session: string = 'main'
  ): Promise<{ status: string; output: string }> {
    return this.request('POST', '/execute_tmux', { session, input });
  }

  public async startBackground(
    command: string,
    session: string = 'background_scan'
  ): Promise<{ status: string; session: string; message: string }> {
    return this.request('POST', '/start_background', { command, session });
  }

  public async pollLogs(
    session: string = 'background_scan'
  ): Promise<{ session: string; active: boolean; delta_logs: string }> {
    const raw = await this.request<{
      session?: string;
      active?: boolean;
      is_active?: boolean;
      delta_logs?: string;
      log_diff?: string;
    }>('GET', `/poll_logs?session=${encodeURIComponent(session)}`);

    return {
      session: raw.session || session,
      active: Boolean(raw.active ?? raw.is_active),
      delta_logs: raw.delta_logs ?? raw.log_diff ?? '',
    };
  }

  public async browserAudit(options: BrowserAuditOptions): Promise<any> {
    const networkPolicy = this.prepareManagedNetworkCall(options.url, options.proxy);
    return this.request('POST', '/browser_audit', {
      ...options,
      proxy: networkPolicy.proxy,
      allowed_hosts: networkPolicy.allowedHosts,
    });
  }

  public async bundleExtract(options: BundleExtractOptions): Promise<any> {
    throw new Error(
      `Bundle extraction runtime is not implemented in the current sandbox image (requested ${options.url})`
    );
  }

  public async httpProbe(options: HttpProbeOptions): Promise<any> {
    const networkPolicy = this.prepareManagedNetworkCall(options.url, options.proxy);
    return this.request('POST', '/http_probe', {
      url: options.url,
      method: options.method || 'GET',
      headers: options.headers || {},
      body: options.body || '',
      proxy: networkPolicy.proxy,
      allowed_hosts: networkPolicy.allowedHosts,
    });
  }

  public async killSwitch(reason: string = 'Manual kill switch triggered'): Promise<any> {
    const result = await this.request('POST', '/emergency_isolate', { reason });
    this.activeNetworkScope = { mode: 'local', targetHosts: [], proxy: null };
    return result;
  }

  public async armCanary(tokenLabel: string = 'default_audit_canary'): Promise<any> {
    return this.request('POST', '/arm_canary', { token_label: tokenLabel });
  }

  public fsRead(relPath: string): { path: string; content: string } {
    const safePath = this.jail.resolveSafePath(relPath);
    if (!fs.existsSync(safePath)) throw new Error(`File not found: ${relPath}`);
    return { path: this.jail.toRelativePosix(safePath), content: fs.readFileSync(safePath, 'utf-8') };
  }

  public fsWrite(relPath: string, content: string): { path: string; bytesWritten: number } {
    const safePath = this.jail.resolveSafePath(relPath);
    const dir = path.dirname(safePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(safePath, content, 'utf-8');
    return {
      path: this.jail.toRelativePosix(safePath),
      bytesWritten: Buffer.byteLength(content, 'utf-8'),
    };
  }

  public async reset(fullCleanup: boolean = false): Promise<{ status: string; message: string }> {
    if (fullCleanup) {
      await this.docker.hardReset(
        this.ratchet.getPublicKeyHex(),
        this.ratchet.getSessionKeyHex()
      );
    } else {
      await this.killSwitch('Reset called');
    }
    this.activeNetworkScope = { mode: 'local', targetHosts: [], proxy: null };
    return { status: 'ok', message: 'Sandbox instance cleanly reset' };
  }
}
