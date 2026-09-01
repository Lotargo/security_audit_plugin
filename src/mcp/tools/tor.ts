import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const RotateTorSchema = z.object({});

export function registerTorTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_rotate_tor_ip',
    'Sends SIGNAL NEWNYM to Tor Control Port to rotate circuit and obtain a fresh exit IP address for WAF/Rate-limit bypass.',
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
          content: [{ type: 'text', text: `Failed to rotate Tor IP: ${err.message}` }],
        };
      }
    }
  );
}
