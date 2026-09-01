import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const HttpProbeSchema = z.object({
  url: z.string().url().describe('Target HTTP/HTTPS URL'),
  method: z.string().optional().default('GET').describe('HTTP Method: GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH'),
  headers: z
    .record(z.string())
    .optional()
    .describe('HTTP headers (including L7 IP spoofing: X-Forwarded-For, Client-IP, etc.)'),
  body: z.string().optional().describe('HTTP Request body string'),
  proxy: z.string().optional().describe('Proxy routing ("tor" or specific proxy URL)'),
});

export function registerProbeTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_http_probe',
    'Sends raw HTTP/HTTPS probe with custom headers, L7 IP spoofing, payload injection, and proxy tunneling.',
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
          content: [{ type: 'text', text: `HTTP probe failed: ${err.message}` }],
        };
      }
    }
  );
}
