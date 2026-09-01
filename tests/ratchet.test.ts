import { describe, it, expect } from 'vitest';
import {
  RatchetBridge,
  decryptPayloadWithAad,
  encryptPayloadWithAad,
} from '../src/mcp/security/ratchet_bridge.js';

describe('RatchetBridge Host Crypto & Signature Verification', () => {
  it('generates valid Ed25519 and 256-bit session keys', () => {
    const ratchet = new RatchetBridge();
    expect(ratchet.getPublicKeyHex()).toMatch(/^[0-9a-f]{64}$/i);
    expect(ratchet.getSessionKeyHex()).toMatch(/^[0-9a-f]{64}$/i);
  });

  it('signs the exact transmitted encrypted envelope', () => {
    const ratchet = new RatchetBridge();
    const method = 'POST';
    const path = '/execute?mode=ci';
    const plaintext = JSON.stringify({ command: 'whoami', token: 'secret-value' });

    const { headers, rawBody } = ratchet.signRequest(method, path, plaintext);

    expect(headers['x-signature-host']).toHaveLength(128);
    expect(headers['x-aad-binding']).toContain(path);
    expect(headers['x-payload-encrypted']).toBe('chacha20-poly1305');
    expect(rawBody.toString('utf-8')).not.toContain('secret-value');

    expect(
      ratchet.verifySignature(
        method,
        path,
        headers['x-ratchet-epoch'],
        headers['x-nonce'],
        rawBody,
        headers['x-signature-host']
      )
    ).toBe(true);
  });

  it('rejects a tampered transmitted body', () => {
    const ratchet = new RatchetBridge();
    const { headers, rawBody } = ratchet.signRequest('POST', '/execute', '{"command":"whoami"}');
    const tampered = Buffer.concat([rawBody, Buffer.from('x')]);

    expect(
      ratchet.verifySignature(
        'POST',
        '/execute',
        headers['x-ratchet-epoch'],
        headers['x-nonce'],
        tampered,
        headers['x-signature-host']
      )
    ).toBe(false);
  });

  it('rejects expired epoch timestamps', () => {
    const ratchet = new RatchetBridge();
    const expiredEpoch = (Math.floor(Date.now() / 1000) - 60).toString();
    expect(
      ratchet.verifySignature(
        'GET',
        '/isolation_status',
        expiredEpoch,
        'testnonce123456',
        '',
        '0'.repeat(128)
      )
    ).toBe(false);
  });

  it('encrypts and decrypts payloads with AAD and rejects tampered AAD', async () => {
    const crypto = await import('node:crypto');
    const key = crypto.randomBytes(32);
    const plaintext = JSON.stringify({ secret_token: 'SuperSecret123', target: 'https://example.com' });
    const aad = 'host_mcp:POST:/execute:1725150000';

    const envelope = encryptPayloadWithAad(plaintext, key, aad);
    const decrypted = decryptPayloadWithAad(
      envelope.ciphertext,
      envelope.nonce,
      envelope.tag,
      key,
      aad,
      envelope.algorithm
    );
    expect(decrypted.toString('utf-8')).toBe(plaintext);

    expect(() =>
      decryptPayloadWithAad(
        envelope.ciphertext,
        envelope.nonce,
        envelope.tag,
        key,
        'tampered_aad_wrong_endpoint',
        envelope.algorithm
      )
    ).toThrow();
  });
});
