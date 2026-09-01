import { describe, it, expect } from 'vitest';
import { SecretRedactor } from '../src/mcp/security/redaction.js';

describe('SecretRedactor Masking Engine', () => {
  it('masks Bearer JWT tokens in text', () => {
    const raw = 'Request sent with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c to endpoint';
    const redacted = SecretRedactor.redact(raw);
    expect(redacted).toContain('Bearer eyJhbG***sw5c');
    expect(redacted).not.toContain('eyJzdWIiOiIxMjM0NTY3ODkw');
  });

  it('masks AWS access keys', () => {
    const raw = 'Found AWS key AKIAIOSFODNN7EXAMPLE in environment dump';
    const redacted = SecretRedactor.redact(raw);
    expect(redacted).toContain('AKIA***MPLE');
    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('masks OpenAI / API keys', () => {
    const raw = 'API key sk-abcdef1234567890abcdef1234567890 loaded';
    const redacted = SecretRedactor.redact(raw);
    expect(redacted).toContain('sk-a***7890');
  });

  it('masks RSA private keys completely', () => {
    const raw = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA04s...\n-----END RSA PRIVATE KEY-----';
    const redacted = SecretRedactor.redact(raw);
    expect(redacted).toContain('-----BEGIN REDACTED PRIVATE KEY-----');
    expect(redacted).toContain('[REDACTED_BY_SECURITY_AUDIT_PLUGIN]');
    expect(redacted).not.toContain('MIIEowIBAAKCAQEA04s');
  });

  it('redacts sensitive headers in header dictionaries', () => {
    const headers = {
      'Authorization': 'Bearer eyJsecretToken12345.67890.abcdef',
      'Cookie': 'sessionid=abc123secretXYZ; csrftoken=999;',
      'Content-Type': 'application/json',
      'X-Forwarded-For': '127.0.0.1',
    };

    const clean = SecretRedactor.redactHeaders(headers);
    expect(clean['Authorization']).toBe('Bear***cdef');
    expect(clean['Cookie']).toBe('sess***999;');
    expect(clean['Content-Type']).toBe('application/json');
    expect(clean['X-Forwarded-For']).toBe('127.0.0.1');
  });

  it('redacts sensitive values in complex JSON objects', () => {
    const data = {
      user: 'admin',
      password: 'SuperSecretPassword123!',
      nested: {
        api_key: 'sk-999988887777666655554444',
      },
    };

    const clean = SecretRedactor.redactObject(data);
    expect(clean.user).toBe('admin');
    expect(clean.password).toBe('Su***3!');
    expect(clean.nested.api_key).toBe('sk-9***4444');
  });
});
