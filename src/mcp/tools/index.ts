import { SandboxBridge } from '../bridge.js';
import { registerScopeTool } from './scope.js';
import { registerTorTool } from './tor.js';
import { registerExecTools } from './exec.js';
import { registerBackgroundTools } from './background.js';
import { registerBrowserTool } from './browser.js';
import { registerBundleTool } from './bundle.js';
import { registerProbeTool } from './probe.js';
import { registerPanicTools } from './panic.js';
import { registerFsTools } from './fs.js';

/**
 * Registers all 12 Security Audit Sandbox MCP Tools on the provided McpServer instance.
 */
export function registerAllTools(server: any, bridge: SandboxBridge): void {
  // 1. Scope & RoE Egress Firewall
  registerScopeTool(server, bridge);

  // 2. Tor Circuit Rotation
  registerTorTool(server, bridge);

  // 3. Execution & Interactive Tmux
  registerExecTools(server, bridge);

  // 4. Background Scanning & Delta Log Polling
  registerBackgroundTools(server, bridge);

  // 5. Stealth Browser & Anti-Fingerprinting
  registerBrowserTool(server, bridge);

  // 6. Bundle Extraction & API Mapping
  registerBundleTool(server, bridge);

  // 7. L7 Probes & IP Spoofing
  registerProbeTool(server, bridge);

  // 8. Panic & Reset Controls
  registerPanicTools(server, bridge);

  // 9. Filesystem Read / Write
  registerFsTools(server, bridge);
}
