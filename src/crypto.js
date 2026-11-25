import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const VERSION_PREFIX = 'v1';

/**
 * Derives or loads a 32-byte AES-256-GCM master key.
 * Supports 64-char hex, base64-encoded 32 bytes, or arbitrary passphrase via scrypt.
 * Falls back to persisting an auto-generated random key file when none is provided.
 */

export function resolveMasterKey({ tokenEncryptionKey = '', masterKeyPath } = {}) {
  const rawKey = String(tokenEncryptionKey || '').trim();
  if (rawKey) {
    if (/^[0-9a-fA-F]{64}$/.test(rawKey)) {
      return { key: Buffer.from(rawKey, 'hex'), source: 'env-hex' };
    }
    const maybeB64 = Buffer.from(rawKey, 'base64');
    if (maybeB64.length === KEY_LENGTH && maybeB64.toString('base64') === rawKey) {
      return { key: maybeB64, source: 'env-base64' };
    }
    return {
      key: crypto.scryptSync(rawKey, 'linkedin-post-scheduler-v1', KEY_LENGTH),
      source: 'env-derived'
    };
  }

  if (!masterKeyPath) {
    throw new Error('Either tokenEncryptionKey or masterKeyPath must be provided.');
  }

  fs.mkdirSync(path.dirname(masterKeyPath), { recursive: true });
  if (fs.existsSync(masterKeyPath)) {
    const stored = fs.readFileSync(masterKeyPath, 'utf8').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(stored)) {
      throw new Error(`Invalid master key format in ${masterKeyPath}. Expected 64 hex chars.`);
    }
    return { key: Buffer.from(stored, 'hex'), source: 'file' };
  }

  const generated = crypto.randomBytes(KEY_LENGTH);
  fs.writeFileSync(masterKeyPath, generated.toString('hex') + '\n', { mode: 0o600 });
  return { key: generated, source: 'generated-file' };
}

/**
 * Authenticated encryption wrapper (AES-256-GCM) for OAuth tokens and secrets at rest.
 */

export class TokenCipher {
  constructor(options = {}) {
    const { key, source } = resolveMasterKey(options);
    if (!Buffer.isBuffer(key) || key.length !== KEY_LENGTH) {
      throw new Error('Encryption key must be exactly 32 bytes.');
    }
    this.#key = key;
    this.keySource = source;
  }

  #key;

  encrypt(plaintext) {
    if (plaintext === null || plaintext === undefined) return null;
    const text = String(plaintext);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.#key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return [
      VERSION_PREFIX,
      iv.toString('base64'),
      authTag.toString('base64'),
      encrypted.toString('base64')
    ].join(':');
  }

  decrypt(payload) {
    if (payload === null || payload === undefined) return null;
    const parts = String(payload).split(':');
    if (parts.length !== 4 || parts[0] !== VERSION_PREFIX) {
      throw new Error('Unsupported or malformed encrypted payload format.');
    }
    const iv = Buffer.from(parts[1], 'base64');
    const authTag = Buffer.from(parts[2], 'base64');
    const ciphertext = Buffer.from(parts[3], 'base64');

    const decipher = crypto.createDecipheriv(ALGORITHM, this.#key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  }
}

/**
 * Produces a deterministic SHA-256 hash of normalized post text for duplicate detection.
 */

export function hashPostContent(content) {
  const normalized = String(content || '')
    .replace(/\r\n/g, '\n')
    .trim();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

export function generateRandomToken(byteLength = 24) {
  return crypto.randomBytes(byteLength).toString('hex');
}
