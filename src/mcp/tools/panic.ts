import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const KillSwitchSchema = z.object({
  reason: z
    .string()
    .optional()
    .default('Manual emergency trigger')
    .describe('Reason for activating emergency network blackout'),
});

export const ResetSchema = z.object({
  full_cleanup: z
    .boolean()
    .optional()
    .default(false)
    .describe('Whether to destroy and recreate the container from clean image'),
});

export function registerPanicTools(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_kill_switch',
    'Emergency Kill Switch: instantly drops all network traffic and flushes connections (conntrack -F).',
    KillSwitchSchema.shape,
    async (args: z.infer<typeof KillSwitchSchema>) => {
      try {
        const res = await bridge.killSwitch(args.reason);
        return {
          content: [
            {
              type: 'text',
              text: `🚨 EMERGENCY KILL SWITCH ENGAGED: ${JSON.stringify(res)}`,
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Kill switch failed: ${err.message}` }],
        };
      }
    }
  );

  server.tool(
    'sandbox_reset',
    'Resets sandbox environment: re-spawns a pristine container instance while preserving report files.',
    ResetSchema.shape,
    async (args: z.infer<typeof ResetSchema>) => {
      try {
        const res = await bridge.reset(args.full_cleanup);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(res, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Sandbox reset failed: ${err.message}` }],
        };
      }
    }
  );
}
