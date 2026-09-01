import * as crypto from 'node:crypto';

export interface SignedHeaders {
  'x-signature-host': string;
  'x-ratchet-epoch': string;
  'x-nonce': string;
  'x-aad-binding': string;
  'x-payload-encrypted'?: string;
  'content-type': string;
}

export interface KeyPairHex {
  publicKeyHex: string;
  privateKeyPem?: string;
}

export interface EncryptedEnvelope {
  algorithm: 'chacha20-poly1305' | 'aes-256-gcm';
  ciphertext: string;
  nonce: string;
  tag: string;
  aad: string;
}

export function encryptPayloadWithAad(
  payload: Buffer | string,
  key32: Buffer,
  aad: string | Buffer
): EncryptedEnvelope {
  if (key32.length !== 32) {
    throw new Error('AEAD key must be exactly 32 bytes');
  }

  const plainBuffer = typeof payload === 'string' ? Buffer.from(payload, 'utf-8') : payload;
  const aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf-8') : aad;
  const nonce = crypto.randomBytes(12);

  let algorithm: 'chacha20-poly1305' | 'aes-256-gcm' = 'chacha20-poly1305';
  if (!crypto.getCiphers().includes('chacha20-poly1305')) {
    algorithm = 'aes-256-gcm';
  }

  const cipher = crypto.createCipheriv(algorithm, key32, nonce, { authTagLength: 16 } as any);
  (cipher as any).setAAD(aadBuffer);
  const ciphertext = Buffer.concat([cipher.update(plainBuffer), cipher.final()]);
  const tag = (cipher as any).getAuthTag();

  return {
    algorithm,
    ciphertext: ciphertext.toString('hex'),
    nonce: nonce.toString('hex'),
    tag: tag.toString('hex'),
    aad: aadBuffer.toString('utf-8'),
  };
}

export function decryptPayloadWithAad(
  ciphertextHex: string,
  nonceHex: string,
  tagHex: string,
  key32: Buffer,
  aad: string | Buffer,
  algorithm?: 'chacha20-poly1305' | 'aes-256-gcm'
): Buffer {
  if (key32.length !== 32) {
    throw new Error('AEAD key must be exactly 32 bytes');
  }

  const cipherBuffer = Buffer.from(ciphertextHex, 'hex');
  const nonce = Buffer.from(nonceHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf-8') : aad;

  const selectedAlgorithm =
    algorithm || (crypto.getCiphers().includes('chacha20-poly1305') ? 'chacha20-poly1305' : 'aes-256-gcm');

  const decipher = crypto.createDecipheriv(selectedAlgorithm, key32, nonce, {
    authTagLength: 16,
  } as any);
  (decipher as any).setAAD(aadBuffer);
  (decipher as any).setAuthTag(tag);

  return Buffer.concat([decipher.update(cipherBuffer), decipher.final()]);
}

/**
 * Host-side control-plane identity and session crypto.
 * Ed25519 authenticates every protected request. Non-empty request bodies are additionally
 * encrypted with a per-MCP-process ChaCha20-Poly1305 session key that is provisioned only
 * into the matching sandbox instance.
 */
export class RatchetBridge {
  private hostPublicKey: crypto.KeyObject;
  private hostPrivateKey: crypto.KeyObject;
  private hostPublicKeyHex: string;
  private sessionKey: Buffer;
  private sessionEpochSeconds: number = 30;

  constructor(customPrivateKeyPem?: string, sessionKeyHex?: string) {
    if (customPrivateKeyPem) {
      this.hostPrivateKey = crypto.createPrivateKey(customPrivateKeyPem);
      this.hostPublicKey = crypto.createPublicKey(this.hostPrivateKey);
    } else {
      const pair = crypto.generateKeyPairSync('ed25519');
      this.hostPublicKey = pair.publicKey;
      this.hostPrivateKey = pair.privateKey;
    }

    const jwk = this.hostPublicKey.export({ format: 'jwk' });
    if (!jwk.x) {
      throw new Error('Failed to export Ed25519 public key in JWK format');
    }
    this.hostPublicKeyHex = Buffer.from(jwk.x, 'base64url').toString('hex');

    this.sessionKey = sessionKeyHex ? Buffer.from(sessionKeyHex, 'hex') : crypto.randomBytes(32);
    if (this.sessionKey.length !== 32) {
      throw new Error('Bridge session key must be exactly 32 bytes');
    }
  }

  public getPublicKeyHex(): string {
    return this.hostPublicKeyHex;
  }

  public getSessionKeyHex(): string {
    return this.sessionKey.toString('hex');
  }

  /**
   * Envelope signature format:
   * `${method}|${pathAndQuery}|${epoch}|${nonce}|${sha256(transmittedBody)}`
   * AAD format:
   * `host_mcp:${method}:${pathAndQuery}:${epoch}`
   */
  public signRequest(
    method: string,
    pathAndQuery: string,
    body: string | Buffer = ''
  ): { headers: SignedHeaders; rawBody: Buffer } {
    const plainBody = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;
    const normalizedMethod = method.toUpperCase();
    const epoch = Math.floor(Date.now() / 1000).toString();
    const requestNonce = crypto.randomBytes(16).toString('hex');
    const aadBinding = `host_mcp:${normalizedMethod}:${pathAndQuery}:${epoch}`;

    let rawBody = plainBody;
    let encryptedAlgorithm: string | undefined;

    if (plainBody.length > 0) {
      const envelope = encryptPayloadWithAad(plainBody, this.sessionKey, aadBinding);
      if (envelope.algorithm !== 'chacha20-poly1305') {
        throw new Error(
          'This runtime requires ChaCha20-Poly1305 support for host-to-sandbox transport encryption'
        );
      }
      rawBody = Buffer.from(
        JSON.stringify({
          algorithm: envelope.algorithm,
          ciphertext: envelope.ciphertext,
          nonce: envelope.nonce,
          tag: envelope.tag,
        }),
        'utf-8'
      );
      encryptedAlgorithm = envelope.algorithm;
    }

    const bodySha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
    const message = `${normalizedMethod}|${pathAndQuery}|${epoch}|${requestNonce}|${bodySha256}`;
    const msgBuffer = Buffer.from(message, 'utf-8');
    const signatureHex = crypto.sign(null, msgBuffer, this.hostPrivateKey).toString('hex');
    this.zeroize(msgBuffer);

    return {
      headers: {
        'x-signature-host': signatureHex,
        'x-ratchet-epoch': epoch,
        'x-nonce': requestNonce,
        'x-aad-binding': aadBinding,
        ...(encryptedAlgorithm ? { 'x-payload-encrypted': encryptedAlgorithm } : {}),
        'content-type': 'application/json',
      },
      rawBody,
    };
  }

  public verifySignature(
    method: string,
    pathAndQuery: string,
    epoch: string,
    nonce: string,
    body: string | Buffer,
    signatureHex: string
  ): boolean {
    const epochNum = parseInt(epoch, 10);
    if (isNaN(epochNum)) return false;

    const now = Math.floor(Date.now() / 1000);
    if (epochNum > now + 5 || now - epochNum > this.sessionEpochSeconds) {
      return false;
    }

    const rawBody = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;
    const bodySha256 = crypto.createHash('sha256').update(rawBody).digest('hex');
    const message = `${method.toUpperCase()}|${pathAndQuery}|${epoch}|${nonce}|${bodySha256}`;
    const msgBuffer = Buffer.from(message, 'utf-8');

    try {
      const valid = crypto.verify(
        null,
        msgBuffer,
        this.hostPublicKey,
        Buffer.from(signatureHex, 'hex')
      );
      this.zeroize(msgBuffer);
      return valid;
    } catch {
      this.zeroize(msgBuffer);
      return false;
    }
  }

  public destroy(): void {
    this.zeroize(this.sessionKey);
  }

  public zeroize(buf: Buffer): void {
    buf.fill(0);
  }
}
