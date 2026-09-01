/**
 * SecretRedactor masks sensitive credentials, tokens, and keys
 * before logging or exporting to audit reports.
 */
export class SecretRedactor {
  private static readonly PATTERNS: Array<{ regex: RegExp; replace: (match: string, ...args: any[]) => string }> = [
    // Bearer / JWT Tokens (eyJ...)
    {
      regex: /Bearer\s+([A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)/gi,
      replace: (_match, p1) => `Bearer ${p1.substring(0, 6)}***${p1.substring(p1.length - 4)}`,
    },
    {
      regex: /\b(eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_.+/=]{10,})\b/g,
      replace: (_match, p1) => `${p1.substring(0, 6)}***${p1.substring(p1.length - 4)}`,
    },
    // AWS Access Key ID (AKIA...)
    {
      regex: /\b(AKIA[0-9A-Z]{16})\b/g,
      replace: (_match, p1) => `${p1.substring(0, 4)}***${p1.substring(p1.length - 4)}`,
    },
    // GitHub Personal Access Token (ghp_, gho_, etc.)
    {
      regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
      replace: (_match, p1) => `${p1.substring(0, 4)}***${p1.substring(p1.length - 4)}`,
    },
    // OpenAI / Generic sk- API keys
    {
      regex: /\b(sk-[A-Za-z0-9]{20,})\b/g,
      replace: (_match, p1) => `${p1.substring(0, 4)}***${p1.substring(p1.length - 4)}`,
    },
    // Private Key blocks (RSA / OpenSSH / EC / PGP)
    {
      regex: /-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----/g,
      replace: () => '-----BEGIN REDACTED PRIVATE KEY-----\n[REDACTED_BY_SECURITY_AUDIT_PLUGIN]\n-----END REDACTED PRIVATE KEY-----',
    },
    // Password fields in JSON / Key-Value
    {
      regex: /(["']?(?:password|passwd|secret|api_key|token|access_token|client_secret)["']?\s*[:=]\s*["'])([^"'\s]{4,})(["'])/gi,
      replace: (_match, p1, p2, p3) => `${p1}${p2.substring(0, 2)}***${p2.substring(p2.length - 2)}${p3}`,
    },
    // Database / HTTP Basic Auth Connection URI Credentials (proto://user:password@host)
    {
      regex: /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:@]+:)([^@\s/]{3,})(@)/g,
      replace: (_match, p1, p2, p3) => `${p1}${p2.substring(0, 2)}***${p3}`,
    },
  ];

  private static readonly SENSITIVE_HEADER_KEYS = new Set([
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'x-auth-token',
    'api-key',
    'x-csrf-token',
    'x-session-id',
  ]);

  private static readonly SENSITIVE_FIELD_KEYS = new Set([
    'password',
    'passwd',
    'secret',
    'api_key',
    'apikey',
    'token',
    'access_token',
    'client_secret',
    'private_key',
    'privkey',
  ]);

  /**
   * Redacts sensitive patterns in raw text strings
   */
  public static redact(text: string): string {
    if (!text || typeof text !== 'string') return text;

    let result = text;
    for (const pattern of this.PATTERNS) {
      result = result.replace(pattern.regex, pattern.replace as any);
    }
    return result;
  }

  /**
   * Redacts sensitive HTTP header maps
   */
  public static redactHeaders(headers: Record<string, string>): Record<string, string> {
    const clean: Record<string, string> = {};
    for (const [key, val] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (this.SENSITIVE_HEADER_KEYS.has(lowerKey)) {
        clean[key] = val.length > 8 ? `${val.substring(0, 4)}***${val.substring(val.length - 4)}` : '***REDACTED***';
      } else {
        clean[key] = this.redact(val);
      }
    }
    return clean;
  }

  /**
   * Recursively redacts sensitive values inside objects
   */
  public static redactObject<T = any>(obj: T): T {
    if (obj === null || obj === undefined) return obj;
    if (typeof obj === 'string') return this.redact(obj) as any;
    if (Array.isArray(obj)) return obj.map((item) => this.redactObject(item)) as any;
    if (typeof obj === 'object') {
      const cloned: Record<string, any> = {};
      for (const [k, v] of Object.entries(obj)) {
        const lowerK = k.toLowerCase();
        if ((lowerK === 'password' || lowerK === 'passwd' || lowerK === 'secret') && typeof v === 'string') {
          cloned[k] = v.length > 4 ? `${v.substring(0, 2)}***${v.substring(v.length - 2)}` : '***REDACTED***';
        } else if (this.SENSITIVE_HEADER_KEYS.has(lowerK) && typeof v === 'string') {
          cloned[k] = v.length > 8 ? `${v.substring(0, 4)}***${v.substring(v.length - 4)}` : '***REDACTED***';
        } else {
          cloned[k] = this.redactObject(v);
        }
      }
      return cloned as T;
    }
    return obj;
  }
}
