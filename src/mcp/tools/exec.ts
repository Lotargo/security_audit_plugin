import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const ExecSchema = z.object({
  command: z.string().describe('Shell command to execute inside the sandbox container'),
  timeout: z.number().optional().default(60).describe('Execution timeout in seconds'),
});

export const InteractiveInputSchema = z.object({
  input: z.string().describe('Input string, response (y/N), password or key sequence to send to tmux'),
  session: z.string().optional().default('main').describe('Name of the tmux session'),
});

export function registerExecTools(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_exec',
    'Executes a CLI command in the sandbox with 30KB output watchdog and automatic log spooling.',
    ExecSchema.shape,
    async (args: z.infer<typeof ExecSchema>) => {
      try {
        const res = await bridge.exec(args.command, args.timeout);
        let outputText = '';
        if (res.stdout) outputText += res.stdout;
        if (res.stderr) outputText += `\n[STDERR]\n${res.stderr}`;

        let summary = `Exit Code: ${res.exit_code}\n`;
        if (res.truncated) {
          summary += `[NOTICE] Output truncated at 30,000 chars. Full dump saved to: ${res.log_path || '/workspace/logs/'}\n`;
        }
        summary += `\n${outputText.trim()}`;

        return {
          content: [{ type: 'text', text: summary }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Execution failed: ${err.message}` }],
        };
      }
    }
  );

  server.tool(
    'sandbox_interactive_input',
    'Sends interactive input or keystrokes to an active tmux session inside the sandbox.',
    InteractiveInputSchema.shape,
    async (args: z.infer<typeof InteractiveInputSchema>) => {
      try {
        const res = await bridge.interactiveInput(args.input, args.session);
        return {
          content: [{ type: 'text', text: JSON.stringify(res, null, 2) }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Interactive input failed: ${err.message}` }],
        };
      }
    }
  );
}
