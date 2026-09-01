import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const BrowserAuditSchema = z.object({
  url: z.string().url().describe('Target web application URL to audit'),
  auth_headers: z
    .record(z.string())
    .optional()
    .describe('Custom authentication headers (Authorization, Cookie, X-Session)'),
  cookies: z
    .array(z.record(z.any()))
    .optional()
    .describe('Pre-authenticated cookies to inject into browser context'),
  proxy: z
    .string()
    .optional()
    .describe('Proxy endpoint ("tor", SOCKS5 or HTTP interceptor)'),
  bypass_turnstile: z
    .boolean()
    .optional()
    .default(true)
    .describe('Enable Bezier curve mouse simulation and human typing for WAF bypass'),
  generate_decoy_noise: z
    .boolean()
    .optional()
    .default(false)
    .describe('Inject synthetic background decoy traffic to obfuscate audit fingerprint'),
  spoof_headers: z
    .record(z.string())
    .optional()
    .describe('L7 IP spoofing headers (X-Forwarded-For, CF-Connecting-IP)'),
});

export function registerBrowserTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_browser_audit',
    'Runs stealth Chromium session with Bezier curves, anti-fingerprinting, proxy support, HAR capture and DOM/cookie analysis.',
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
          content: [{ type: 'text', text: `Browser audit failed: ${err.message}` }],
        };
      }
    }
  );
}
