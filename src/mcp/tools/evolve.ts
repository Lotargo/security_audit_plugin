/**
 * Trusted operator-only Evolve tool definitions.
 *
 * IMPORTANT: this module is intentionally NOT registered by registerAllTools().
 * The default MCP server is agent-facing, so exposing Evolve state or allowing
 * feedback writes there would reveal the deception boundary and permit profile poisoning.
 */
import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const EvolveStatusSchema = z.object({});

export const EvolveObserveSchema = z.object({
  category: z
    .string()
    .min(1)
    .max(96)
    .describe('Defensive behavior category, for example credential_access or discovery'),
  technique: z
    .string()
    .min(1)
    .max(96)
    .describe('Validated TTP/behavior label observed during the audit or deception phase'),
  evidence: z
    .string()
    .min(1)
    .max(4000)
    .describe('Concise evidence supporting the observation. Do not include provider credentials.'),
  severity: z
    .number()
    .int()
    .min(1)
    .max(5)
    .optional()
    .default(3)
    .describe('Defensive significance from 1 (low) to 5 (critical)'),
  path: z
    .string()
    .max(1024)
    .optional()
    .describe('Optional in-sandbox artifact path associated with the observation'),
});

export function registerTrustedEvolveTools(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_evolve_status',
    'Returns the current Evolve adaptive-deception generation, observed behavior patterns, and deterministic defensive recommendations.',
    EvolveStatusSchema.shape,
    async (_args: z.infer<typeof EvolveStatusSchema>) => {
      try {
        const result = await bridge.evolveStatus();
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to read Evolve status: ${err.message}` }],
        };
      }
    }
  );

  server.tool(
    'sandbox_evolve_observe',
    'Records a validated defensive TTP observation into the Evolve behavior memory. This updates the next-generation defensive profile but cannot widen network scope or disable isolation.',
    EvolveObserveSchema.shape,
    async (args: z.infer<typeof EvolveObserveSchema>) => {
      try {
        const result = await bridge.evolveObserve(args);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to record Evolve observation: ${err.message}` }],
        };
      }
    }
  );
}
