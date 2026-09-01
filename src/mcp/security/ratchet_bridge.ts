import * as crypto from 'node:crypto';

export interface SignedHeaders {
  'x-signature-host': string;
  'x-ratchet-epoch': string;
  'x-nonce': string;
  'content-type': string;
}

export interface KeyPairHex {
  publicKeyHex: string;
  privateKeyPem?: string;
}

/**
 * RatchetBridge provides cryptographic signing and epoch tracking
 * for the host-to-sandbox control plane (Ed25519 + ChaCha20 / SHA-256).
 */
export class RatchetBridge {
  private hostPublicKey: crypto.KeyObject;
  private hostPrivateKey: crypto.KeyObject;
  private hostPublicKeyHex: string;
  private sessionEpochSeconds: number = 30;

  constructor(customPrivateKeyPem?: string) {
    if (customPrivateKeyPem) {
      this.hostPrivateKey = crypto.createPrivateKey(customPrivateKeyPem);
      this.hostPublicKey = crypto.createPublicKey(this.hostPrivateKey);
    } else {
      const pair = crypto.generateKeyPairSync('ed25519');
      this.hostPublicKey = pair.publicKey;
      this.hostPrivateKey = pair.privateKey;
    }

    // Export raw 32-byte Ed25519 public key as hex
    const jwk = this.hostPublicKey.export({ format: 'jwk' });
    if (!jwk.x) {
      throw new Error('Failed to export Ed25519 public key in JWK format');
    }
    const rawPubBuffer = Buffer.from(jwk.x, 'base64url');
    this.hostPublicKeyHex = rawPubBuffer.toString('hex');
  }

  /**
   * Returns the raw 32-byte public key as hex for passing to sandbox container (HOST_PUBKEY_HEX)
   */
  public getPublicKeyHex(): string {
    return this.hostPublicKeyHex;
  }

  /**
   * Signs an HTTP request payload for sending to sandbox-daemon
   * Envelope format: `${method}|${path}|${epoch}|${nonce}|${bodySha256Hex}`
   */
  public signRequest(
    method: string,
    path: string,
    body: string | Buffer = ''
  ): { headers: SignedHeaders; rawBody: Buffer } {
    const rawBody = typeof body === 'string' ? Buffer.from(body, 'utf-8') : body;
    const bodySha256 = crypto.createHash('sha256').update(rawBody).digest('hex');

    const epoch = Math.floor(Date.now() / 1000).toString();
    const nonce = crypto.randomBytes(16).toString('hex');

    const message = `${method.toUpperCase()}|${path}|${epoch}|${nonce}|${bodySha256}`;
    const msgBuffer = Buffer.from(message, 'utf-8');

    const signatureBuffer = crypto.sign(null, msgBuffer, this.hostPrivateKey);
    const signatureHex = signatureBuffer.toString('hex');

    // Secure wipe temporary message buffer
    this.zeroize(msgBuffer);

    return {
      headers: {
        'x-signature-host': signatureHex,
        'x-ratchet-epoch': epoch,
        'x-nonce': nonce,
        'content-type': 'application/json',
      },
      rawBody,
    };
  }

  /**
   * Verifies an incoming or test envelope
   */
  public verifySignature(
    method: string,
    path: string,
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
    const message = `${method.toUpperCase()}|${path}|${epoch}|${nonce}|${bodySha256}`;
    const msgBuffer = Buffer.from(message, 'utf-8');

    try {
      const sigBuffer = Buffer.from(signatureHex, 'hex');
      const valid = crypto.verify(null, msgBuffer, this.hostPublicKey, sigBuffer);
      this.zeroize(msgBuffer);
      return valid;
    } catch {
      this.zeroize(msgBuffer);
      return false;
    }
  }

  /**
   * Overwrites sensitive memory buffer with zeros
   */
  public zeroize(buf: Buffer): void {
    buf.fill(0);
  }
}
