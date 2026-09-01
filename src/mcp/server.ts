import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { SandboxBridge } from './bridge.js';
import { registerAllTools } from './tools/index.js';

export interface ServerOptions {
  workspaceRoot?: string;
  hostPort?: number;
}

/**
 * Creates and initializes the Security Audit MCP Server
 */
export async function createMcpServer(options: ServerOptions = {}): Promise<{
  server: McpServer;
  bridge: SandboxBridge;
  start: () => Promise<void>;
}> {
  const workspaceRoot = options.workspaceRoot || process.cwd();
  const hostPort = options.hostPort || 9999;

  const server = new McpServer({
    name: 'security-audit-sandbox',
    version: '0.4.0',
  });

  const bridge = new SandboxBridge({
    workspaceRoot,
    hostPort,
  });

  // Register all 12 sandbox tools
  registerAllTools(server, bridge);

  const start = async () => {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    // Log to stderr so stdout remains clean for MCP JSON-RPC
    console.error(`[SecurityAuditPlugin] MCP Server connected via STDIO (Workspace: ${workspaceRoot})`);
  };

  return {
    server,
    bridge,
    start,
  };
}

// Direct execution entrypoint
if (process.argv[1] && process.argv[1].endsWith('server.js')) {
  createMcpServer()
    .then((inst) => inst.start())
    .catch((err) => {
      console.error('[SecurityAuditPlugin] Fatal MCP Server Error:', err);
      process.exit(1);
    });
}
