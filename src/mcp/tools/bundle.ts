import { z } from 'zod';
import { SandboxBridge } from '../bridge.js';

export const BundleExtractSchema = z.object({
  url: z.string().url().describe('Target web application entrypoint URL'),
  proxy: z.string().optional().describe('Proxy configuration for downloading bundles'),
  out_dir: z
    .string()
    .optional()
    .default('/workspace/extracted_bundles')
    .describe('Directory to save extracted scripts, source maps, and API topology'),
});

export function registerBundleTool(server: any, bridge: SandboxBridge) {
  server.tool(
    'sandbox_bundle_extract',
    'Downloads client JS bundles using TLS impersonation, unpacks Source Maps, and maps REST/GraphQL/gRPC-Web API routes.',
    BundleExtractSchema.shape,
    async (args: z.infer<typeof BundleExtractSchema>) => {
      try {
        const res = await bridge.bundleExtract(args);
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
          content: [{ type: 'text', text: `Bundle extraction failed: ${err.message}` }],
        };
      }
    }
  );
}
