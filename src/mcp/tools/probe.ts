import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const HttpProbeSchema = z.object({
  url: z.string().url().describe('In-scope HTTP/HTTPS URL'),
  method: z
    .string()
    .optional()
    .default('GET')
    .describe('HTTP method: GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'),
  headers: z.record(z.string()).optional().describe('Custom HTTP request headers'),
  body: z.string().optional().describe('HTTP request body string'),
  proxy: z
    .enum(['tor'])
    .optional()
    .describe('Use managed Tor routing when the active sandbox scope was configured with proxy="tor"'),
});

export function registerProbeTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_http_probe',
    'Sends a scoped HTTP/HTTPS request with custom method, headers and body, enforcing the active RoE host list across redirects.',
    HttpProbeSchema.shape,
    async (args: z.infer<typeof HttpProbeSchema>) => {
      try {
        const res = await bridge.httpProbe(args);
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
          content: [{ type: 'text', text: `HTTP probe failed: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
