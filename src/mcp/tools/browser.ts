import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const BrowserAuditSchema = z.object({
  url: z.string().url().describe('In-scope target web application URL to audit'),
  auth_headers: z
    .record(z.string())
    .optional()
    .describe('Custom authentication headers (Authorization, Cookie, X-Session)'),
  cookies: z
    .array(z.record(z.any()))
    .optional()
    .describe('Pre-authenticated cookies to inject into browser context'),
  proxy: z
    .enum(['tor'])
    .optional()
    .describe('Use managed Tor routing when the active sandbox scope was configured with proxy="tor"'),
  bypass_turnstile: z
    .boolean()
    .optional()
    .default(true)
    .describe('Enable human-like cursor, delay, and scrolling behavior; this does not guarantee challenge bypass'),
  generate_decoy_noise: z
    .boolean()
    .optional()
    .default(false)
    .describe('Generate synthetic background requests during the scoped browser audit'),
  spoof_headers: z
    .record(z.string())
    .optional()
    .describe('Additional HTTP headers to send from the browser context'),
  allow_private: z
    .boolean()
    .optional()
    .default(false)
    .describe('Allow audit of RFC1918 / loopback endpoints when explicitly in scope'),
});

export function registerBrowserTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_browser_audit',
    'Runs a scoped Chromium audit with anti-fingerprinting, human-like interaction, WAF heuristics, DOM/cookie analysis, and per-request RoE enforcement.',
    BrowserAuditSchema.shape,
    async (args: z.infer<typeof BrowserAuditSchema>) => {
      try {
        const res = await bridge.browserAudit(args);
        return {
          content: [
            {
              type: 'text',
              text: typeof res === 'string' ? res : JSON.stringify(res, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Browser audit failed: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
