import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SandboxBridge } from './bridge.js';
import { registerAllTools } from './tools/index.js';

export interface ServerOptions {
  workspaceRoot?: string;
  hostPort?: number;
}

export async function createMcpServer(options: ServerOptions = {}): Promise<{
  server: McpServer;
  bridge: SandboxBridge;
  start: () => Promise<void>;
}> {
  const workspaceRoot = options.workspaceRoot || process.cwd();
  const hostPort = options.hostPort || 9999;

  const server = new McpServer({
    name: 'security-audit-sandbox',
    version: '0.6.0',
  });

  const bridge = new SandboxBridge({ workspaceRoot, hostPort });
  registerAllTools(server, bridge);

  const start = async () => {
    // The MCP process owns the ephemeral Ed25519 identity + AEAD session key.
    // Start or re-key the sandbox before exposing tools to the agent.
    await bridge.ensureRuntime();

    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(
      `[SecurityAuditPlugin] MCP Server connected via STDIO (Workspace: ${workspaceRoot}, sandbox: authenticated)`
    );
  };

  return { server, bridge, start };
}

if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  createMcpServer()
    .then((inst) => inst.start())
    .catch((err) => {
      console.error('[SecurityAuditPlugin] Fatal MCP Server Error:', err);
      process.exit(1);
    });
}
