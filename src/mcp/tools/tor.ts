import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const RotateTorSchema = z.object({});

export function registerTorTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_rotate_tor_ip',
    'Requests a new Tor circuit via the cookie-authenticated localhost ControlPort. Requires an active Tor-enabled audit scope.',
    RotateTorSchema.shape,
    async (_args: z.infer<typeof RotateTorSchema>) => {
      try {
        const result = await bridge.rotateTor();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to rotate Tor IP: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
