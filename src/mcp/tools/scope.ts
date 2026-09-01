import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const SetScopeSchema = z.object({
  mode: z.enum(['local', 'remote', 'hybrid']).describe('Audit execution mode'),
  targets: z
    .array(z.string())
    .optional()
    .describe('List of allowed target domains, IPs, or URLs for egress allowlist'),
  proxy: z
    .string()
    .optional()
    .describe('Upstream proxy string: "tor", "socks5://127.0.0.1:9050", "http://127.0.0.1:8080" (Burp/Caido/ZAP)'),
  ca_cert_b64: z
    .string()
    .optional()
    .describe('Base64-encoded custom CA certificate for Burp/Caido/ZAP interception'),
  arm_canaries: z
    .boolean()
    .optional()
    .default(true)
    .describe('Whether to arm decoy canary honeytoken files (.aws, .ssh, .env)'),
  allowed_cidrs: z
    .array(z.string())
    .optional()
    .describe('Explicit CIDRs to allow (overrides default allowlist)'),
  denied_cidrs: z
    .array(z.string())
    .optional()
    .describe('Explicit CIDRs to block (e.g. private subnets)'),
});

export function registerScopeTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_set_scope',
    'Configures RoE audit scope, network egress firewall rules (nftables), proxy routing (Tor/Burp/Caido) and arms canary deception tripwires.',
    SetScopeSchema.shape,
    async (args: z.infer<typeof SetScopeSchema>) => {
      try {
        const result = await bridge.setScope(args);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'success', scope: args, firewall: result }, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to set scope: ${err.message}` }],
        };
      }
    }
  );
}
