import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';
import { agentSafeError } from '../security/agent_error.js';

export const SetScopeSchema = z.object({
  mode: z.enum(['local', 'remote', 'hybrid']).describe('Audit execution mode'),
  targets: z
    .array(z.string())
    .optional()
    .describe(
      'Allowed target domains, single IPs, CIDRs, or URLs. Domains/URLs are resolved on the trusted host and pinned to explicit IP CIDRs before nftables is provisioned. Tor scopes require explicit host-level targets.'
    ),
  proxy: z
    .enum(['tor'])
    .optional()
    .describe('Enable the sandbox-managed Tor proxy. External upstream HTTP/SOCKS proxies are not exposed until process-level containment is implemented.'),
  arm_canaries: z
    .boolean()
    .optional()
    .default(true)
    .describe('Whether to arm decoy canary honeytoken files (.aws, .ssh, .env)'),
  allowed_cidrs: z
    .array(z.string())
    .optional()
    .describe(
      'Additional explicit IP/CIDR ranges for direct L3 egress. Unbounded /0 allowlists are rejected.'
    ),
  denied_cidrs: z
    .array(z.string())
    .optional()
    .describe('Explicit CIDRs to block. Deny rules take precedence over target/allowlist rules.'),
});

export function registerScopeTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_set_scope',
    'Configures the Rules-of-Engagement scope, pinned nftables egress policy, optional managed Tor routing, and canary tripwires.',
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
          content: [{ type: 'text', text: `Failed to set scope: ${agentSafeError(err, 'operation unavailable')}` }],
        };
      }
    }
  );
}
