import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TokenCipher, hashPostContent } from '../src/crypto.js';

test('TokenCipher encrypts and decrypts with unique random IVs and tamper detection', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'li-crypto-'));
  try {
    const cipher = new TokenCipher({
      tokenEncryptionKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    });

    const plaintext = 'AQV_super_secret_linkedin_access_token';
    const enc1 = cipher.encrypt(plaintext);
    const enc2 = cipher.encrypt(plaintext);

    assert.ok(enc1.startsWith('v1:'));
    assert.notEqual(enc1, enc2, 'Each encryption must use a fresh random IV');
    assert.equal(cipher.decrypt(enc1), plaintext);
    assert.equal(cipher.decrypt(enc2), plaintext);

    // Tamper with ciphertext
    const parts = enc1.split(':');
    const tamperedBytes = Buffer.from(parts[3], 'base64');
    tamperedBytes[0] ^= 0xff;
    parts[3] = tamperedBytes.toString('base64');
    assert.throws(() => cipher.decrypt(parts.join(':')));

    // Auto-generated master key file persists across instances
    const keyPath = path.join(tmpDir, '.master.key');
    const c1 = new TokenCipher({ masterKeyPath: keyPath });
    const c2 = new TokenCipher({ masterKeyPath: keyPath });
    assert.equal(c1.keySource, 'generated-file');
    assert.equal(c2.keySource, 'file');
    const secret = c1.encrypt('client_secret_value');
    assert.equal(c2.decrypt(secret), 'client_secret_value');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('hashPostContent normalizes CRLF and surrounding whitespace', () => {
  const h1 = hashPostContent('Hello LinkedIn!\r\nSecond line  ');
  const h2 = hashPostContent('  Hello LinkedIn!\nSecond line');
  const h3 = hashPostContent('Different content');
  assert.equal(h1, h2);
  assert.notEqual(h1, h3);
});
