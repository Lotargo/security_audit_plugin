import { describe, it, expect } from 'vitest';
import { RatchetBridge } from '../src/mcp/security/ratchet_bridge.js';

describe('RatchetBridge Host Crypto & Signature Verification', () => {
  const ratchet = new RatchetBridge();

  it('generates a valid 32-byte (64 hex chars) Ed25519 public key', () => {
    const pubkeyHex = ratchet.getPublicKeyHex();
    expect(pubkeyHex).toHaveLength(64);
    expect(/^[0-9a-f]{64}$/i.test(pubkeyHex)).toBe(true);
  });

  it('correctly signs requests and verifies valid envelopes', () => {
    const method = 'POST';
    const path = '/execute';
    const body = JSON.stringify({ command: 'whoami', timeout: 30 });

    const { headers, rawBody } = ratchet.signRequest(method, path, body);

    expect(headers['x-signature-host']).toBeDefined();
    expect(headers['x-ratchet-epoch']).toBeDefined();
    expect(headers['x-nonce']).toBeDefined();
    expect(headers['x-signature-host']).toHaveLength(128); // 64-byte Ed25519 signature in hex

    const isValid = ratchet.verifySignature(
      method,
      path,
      headers['x-ratchet-epoch'],
      headers['x-nonce'],
      rawBody,
      headers['x-signature-host']
    );

    expect(isValid).toBe(true);
  });

  it('rejects tampered body with invalid signature', () => {
    const method = 'POST';
    const path = '/execute';
    const body = JSON.stringify({ command: 'whoami' });

    const { headers } = ratchet.signRequest(method, path, body);
    const tamperedBody = JSON.stringify({ command: 'rm -rf /' });

    const isValid = ratchet.verifySignature(
      method,
      path,
      headers['x-ratchet-epoch'],
      headers['x-nonce'],
      tamperedBody,
      headers['x-signature-host']
    );

    expect(isValid).toBe(false);
  });

  it('rejects expired epoch timestamps', () => {
    const method = 'GET';
    const path = '/isolation_status';
    const expiredEpoch = (Math.floor(Date.now() / 1000) - 60).toString(); // 60s in the past
    const nonce = 'testnonce123456';
    const body = '';

    const isValid = ratchet.verifySignature(
      method,
      path,
      expiredEpoch,
      nonce,
      body,
      '0'.repeat(128)
    );

    expect(isValid).toBe(false);
  });

  it('encrypts and decrypts payloads with Authenticated Associated Data (AAD)', async () => {
    const { encryptPayloadWithAad, decryptPayloadWithAad } = await import(
      '../src/mcp/security/ratchet_bridge.js'
    );
    const crypto = await import('node:crypto');

    const key = crypto.randomBytes(32);
    const plaintext = JSON.stringify({ secret_token: 'SuperSecret123', target: 'https://example.com' });
    const aad = 'host_mcp:POST:/execute:1725150000';

    const envelope = encryptPayloadWithAad(plaintext, key, aad);
    expect(envelope.ciphertext).toBeDefined();
    expect(envelope.nonce).toHaveLength(24); // 12 bytes = 24 hex
    expect(envelope.tag).toHaveLength(32); // 16 bytes = 32 hex

    const decrypted = decryptPayloadWithAad(
      envelope.ciphertext,
      envelope.nonce,
      envelope.tag,
      key,
      aad
    );
    expect(decrypted.toString('utf-8')).toBe(plaintext);

    // Tampered AAD must fail decryption
    expect(() => {
      decryptPayloadWithAad(
        envelope.ciphertext,
        envelope.nonce,
        envelope.tag,
        key,
        'tampered_aad_wrong_endpoint'
      );
    }).toThrow();
  });
});
