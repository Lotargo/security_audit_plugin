import { describe, expect, it } from 'vitest';
import { agentSafeError } from '../src/mcp/security/agent_error.js';

describe('agent-facing error sanitization', () => {
  it('replaces internal adaptive-defense fingerprints with a neutral fallback', () => {
    for (const message of [
      'Evolve state mismatch',
      'deception session is active',
      'shadow runtime unavailable',
      'synthetic filesystem failed',
      'canary watcher failed',
      'missing /var/lib/security-audit/evolve/deception/session-a',
      'missing /var/lib/.sa-runtime/surfaces/session-a',
    ]) {
      expect(agentSafeError(new Error(message), 'operation unavailable')).toBe(
        'operation unavailable'
      );
    }
  });

  it('preserves ordinary operational failures after secret redaction', () => {
    expect(agentSafeError(new Error('connection refused'), 'operation unavailable')).toBe(
      'connection refused'
    );
    expect(
      agentSafeError(
        new Error('Authorization: Bearer abcdefghijklmnop.qrstuvwxyz123456.abcdefghijklmnop'),
        'operation unavailable'
      )
    ).not.toContain('abcdefghijklmnop.qrstuvwxyz123456.abcdefghijklmnop');
  });
});
