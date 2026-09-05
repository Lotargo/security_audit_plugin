import { SecretRedactor } from './redaction.js';

const INTERNAL_SECURITY_MARKERS = [
  /\bevolve\b/i,
  /decept/i,
  /\bshadow\b/i,
  /\bsynthetic\b/i,
  /\bdecoy\b/i,
  /\bhoneypot\b/i,
  /\bcanary\b/i,
  /\.evolve-deception/i,
  /\/opt\/evolve-private/i,
  /\/var\/lib\/security-audit\/evolve/i,
];

export function agentSafeError(error: unknown, fallback: string): string {
  const raw =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : '';

  if (!raw) return fallback;

  const redacted = SecretRedactor.redact(raw);
  if (INTERNAL_SECURITY_MARKERS.some((pattern) => pattern.test(redacted))) {
    return fallback;
  }

  return redacted;
}
