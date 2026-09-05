import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const StartBackgroundSchema = z.object({
  command: z.string().describe('Long-running shell command (e.g. nmap, nikto, dirb, ffuf)'),
  session: z
    .string()
    .optional()
    .default('background_scan')
    .describe('Identifier for background tmux session'),
});

export const PollLogsSchema = z.object({
  session: z
    .string()
    .optional()
    .default('background_scan')
    .describe('Session identifier to poll incremental logs from'),
});

export function registerBackgroundTools(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_start_background',
    'Starts a long-running scan or fuzzing process in a background tmux session without blocking the agent.',
    StartBackgroundSchema.shape,
    async (args: z.infer<typeof StartBackgroundSchema>) => {
      try {
        const res = await bridge.startBackground(args.command, args.session);
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to start background job: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );

  server.tool(
    'sandbox_poll_logs',
    'Retrieves new incremental output lines and current running status from a background session.',
    PollLogsSchema.shape,
    async (args: z.infer<typeof PollLogsSchema>) => {
      try {
        const res = await bridge.pollLogs(args.session);
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to poll background logs: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
