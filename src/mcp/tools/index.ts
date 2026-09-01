import { SandboxBridge } from '../bridge.js';
import { registerScopeTool } from './scope.js';
import { registerTorTool } from './tor.js';
import { registerExecTools } from './exec.js';
import { registerBackgroundTools } from './background.js';
import { registerBrowserTool } from './browser.js';
import { registerProbeTool } from './probe.js';
import { registerPanicTools } from './panic.js';
import { registerFsTools } from './fs.js';

/**
 * Registers the 12 implemented Security Audit Sandbox MCP tools.
 */
export function registerAllTools(server: any, bridge: SandboxBridge): void {
  // 1. Scope & RoE Egress Firewall
  registerScopeTool(server, bridge);

  // 2. Tor Circuit Rotation
  registerTorTool(server, bridge);

  // 3-4. Execution & Interactive Tmux
  registerExecTools(server, bridge);

  // 5-6. Background Scanning & Delta Log Polling
  registerBackgroundTools(server, bridge);

  // 7. Stealth Browser
  registerBrowserTool(server, bridge);

  // 8. Scoped HTTP/HTTPS Probes
  registerProbeTool(server, bridge);

  // 9-10. Panic & Reset Controls
  registerPanicTools(server, bridge);

  // 11-12. Filesystem Read / Write
  registerFsTools(server, bridge);
}
