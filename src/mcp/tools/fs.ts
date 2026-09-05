import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const FsReadSchema = z.object({
  path: z.string().describe('Relative path to file inside workspace (e.g. "reports/audit-report.sarif")'),
});

export const FsWriteSchema = z.object({
  path: z.string().describe('Relative path to destination file inside workspace'),
  content: z.string().describe('String content to write into file'),
});

export function registerFsTools(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_fs_read',
    'Reads an audit report, plan, or file from the isolated workspace with strict Path Traversal protection.',
    FsReadSchema.shape,
    async (args: z.infer<typeof FsReadSchema>) => {
      try {
        const file = await bridge.fsRead(args.path);
        return {
          content: [
            {
              type: 'text',
              text: file.content,
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to read file: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );

  server.tool(
    'sandbox_fs_write',
    'Writes an audit artifact, SARIF report, or OPPLAN to the workspace with strict Path Traversal protection.',
    FsWriteSchema.shape,
    async (args: z.infer<typeof FsWriteSchema>) => {
      try {
        const res = await bridge.fsWrite(args.path, args.content);
        return {
          content: [
            {
              type: 'text',
              text: `File written successfully: ${res.path} (${res.bytesWritten} bytes)`,
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to write file: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
