import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SandboxBridge } from '../src/mcp/bridge.js';
import { registerAllTools } from '../src/mcp/tools/index.js';

describe('MCP Tools Registration & Dispatch Test Suite', () => {
  let registeredTools: Map<
    string,
    { description: string; schema: any; handler: (args: any) => Promise<any> }
  >;
  let mockServer: any;
  let mockBridge: SandboxBridge;

  beforeEach(() => {
    registeredTools = new Map();
    mockServer = {
      tool: vi.fn((name: string, description: string, schema: any, handler: any) => {
        registeredTools.set(name, { description, schema, handler });
      }),
    };

    mockBridge = new SandboxBridge({
      workspaceRoot: process.cwd(),
      hostPort: 9999,
    });
  });

  it('registers all expected MCP tools on server', () => {
    registerAllTools(mockServer, mockBridge);

    const expectedTools = [
      'sandbox_set_scope',
      'sandbox_rotate_tor_ip',
      'sandbox_exec',
      'sandbox_interactive_input',
      'sandbox_start_background',
      'sandbox_poll_logs',
      'sandbox_browser_audit',
      'sandbox_http_probe',
      'sandbox_kill_switch',
      'sandbox_reset',
      'sandbox_fs_read',
      'sandbox_fs_write',
    ];

    expect(registeredTools.size).toBe(expectedTools.length);
    expect(registeredTools.has('sandbox_evolve_status')).toBe(false);
    expect(registeredTools.has('sandbox_evolve_observe')).toBe(false);
    for (const toolName of expectedTools) {
      expect(registeredTools.has(toolName)).toBe(true);
      const toolDef = registeredTools.get(toolName)!;
      expect(toolDef.description.length).toBeGreaterThan(10);
      expect(typeof toolDef.handler).toBe('function');
    }
  });

  describe('Tool execution and bridge forwarding', () => {
    beforeEach(() => {
      registerAllTools(mockServer, mockBridge);
    });

    it('sandbox_set_scope forwards parameters and returns success JSON', async () => {
      vi.spyOn(mockBridge, 'setScope').mockResolvedValue({
        status: 'applied',
        rules_count: 5,
      });

      const tool = registeredTools.get('sandbox_set_scope')!;
      const res = await tool.handler({
        mode: 'remote',
        targets: ['https://api.example.com'],
        proxy: 'tor',
      });

      expect(res.isError).toBeUndefined();
      expect(res.content[0].type).toBe('text');
      const parsed = JSON.parse(res.content[0].text);
      expect(parsed.status).toBe('success');
      expect(parsed.scope.mode).toBe('remote');
      expect(parsed.firewall.rules_count).toBe(5);
    });

    it('sandbox_rotate_tor_ip returns new Tor circuit details', async () => {
      vi.spyOn(mockBridge, 'rotateTor').mockResolvedValue({
        status: 'rotated',
        message: 'SIGNAL NEWNYM sent',
        exit_ip: '185.220.101.5',
      });

      const tool = registeredTools.get('sandbox_rotate_tor_ip')!;
      const res = await tool.handler({});

      expect(res.content[0].type).toBe('text');
      const parsed = JSON.parse(res.content[0].text);
      expect(parsed.status).toBe('rotated');
      expect(parsed.exit_ip).toBe('185.220.101.5');
    });

    it('sandbox_exec handles successful command execution', async () => {
      vi.spyOn(mockBridge, 'exec').mockResolvedValue({
        stdout: 'audit output clean',
        stderr: '',
        exit_code: 0,
        truncated: false,
      });

      const tool = registeredTools.get('sandbox_exec')!;
      const res = await tool.handler({ command: 'semgrep --version', timeout: 30 });

      expect(res.content[0].text).toContain('audit output clean');
      expect(res.content[0].text).toContain('Exit Code: 0');
    });

    it('sandbox_kill_switch triggers emergency network blackout', async () => {
      vi.spyOn(mockBridge, 'killSwitch').mockResolvedValue({
        isolated: true,
        reason: 'Canary tripwire breached',
      });

      const tool = registeredTools.get('sandbox_kill_switch')!;
      const res = await tool.handler({ reason: 'Canary tripwire breached' });

      expect(res.content[0].type).toBe('text');
      expect(res.content[0].text).toContain('EMERGENCY KILL SWITCH ENGAGED');
      expect(res.content[0].text).toContain('Canary tripwire breached');
    });

    it('sandbox_fs_write and sandbox_fs_read handle safe workspace files', async () => {
      vi.spyOn(mockBridge, 'fsWrite').mockResolvedValue({
        path: '/workspace/reports/test.txt',
        bytesWritten: 14,
      });
      vi.spyOn(mockBridge, 'fsRead').mockResolvedValue({
        path: '/workspace/reports/test.txt',
        content: 'Report Content',
      });

      const writeTool = registeredTools.get('sandbox_fs_write')!;
      const writeRes = await writeTool.handler({
        path: 'reports/test.txt',
        content: 'Report Content',
      });
      expect(writeRes.content[0].text).toContain('File written successfully');
      expect(writeRes.content[0].text).toContain('14 bytes');

      const readTool = registeredTools.get('sandbox_fs_read')!;
      const readRes = await readTool.handler({
        path: 'reports/test.txt',
      });
      expect(readRes.content[0].text).toBe('Report Content');
    });

    it('returns formatted error object when bridge operation throws', async () => {
      vi.spyOn(mockBridge, 'exec').mockRejectedValue(new Error('Connection refused to sandbox'));

      const tool = registeredTools.get('sandbox_exec')!;
      const res = await tool.handler({ command: 'nmap 127.0.0.1' });

      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain('Execution failed: Connection refused to sandbox');
    });
  });
});
