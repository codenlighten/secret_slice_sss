// The 2024 secretslices.com app could encrypt a secret with a password before
// splitting it (CryptoJS.AES.encrypt(text, password)). Recovering such a
// secret yields the ciphertext, which this module decrypts.
//
// The scheme is OpenSSL's legacy "Salted__" format: AES-256-CBC with the key
// and IV derived from the password by one round of MD5 (EVP_BytesToKey). That
// derivation is weak, so this module only decrypts; it offers no encryption.

import { fail } from './errors.js';

const MD5_SHIFTS = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));

function md5(data) {
  const total = Math.ceil((data.length + 9) / 64) * 64;
  const block = new Uint8Array(total);
  block.set(data);
  block[data.length] = 0x80;
  const view = new DataView(block.buffer);
  view.setUint32(total - 8, (data.length << 3) >>> 0, true);
  view.setUint32(total - 4, Math.floor(data.length / 0x20000000), true);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let offset = 0; offset < total; offset += 64) {
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      f = (f + a + MD5_K[i] + view.getUint32(offset + g * 4, true)) | 0;
      const shift = MD5_SHIFTS[(i >> 4) * 4 + (i % 4)];
      a = d; d = c; c = b;
      b = (b + ((f << shift) | (f >>> (32 - shift)))) | 0;
    }
    a0 = (a0 + a) | 0; b0 = (b0 + b) | 0; c0 = (c0 + c) | 0; d0 = (d0 + d) | 0;
  }
  block.fill(0);
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((word, i) => outView.setUint32(i * 4, word >>> 0, true));
  return out;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
}

/** True if `text` looks like a secret encrypted by the 2024 app. */
export function isPasswordEncrypted(text) {
  return typeof text === 'string' && /^U2FsdGVkX1[A-Za-z0-9+/]+={0,2}$/.test(text.trim());
}

/**
 * @param {string} ciphertext the recovered "U2FsdGVkX1..." text
 * @param {string} password
 * @returns {Promise<string>} the original secret
 */
export async function decryptWithPassword(ciphertext, password) {
  if (!isPasswordEncrypted(ciphertext)) {
    fail('ERR_INVALID_ARGUMENT', 'this is not a secret encrypted by the SecretSlices app');
  }
  if (typeof password !== 'string') fail('ERR_INVALID_ARGUMENT', 'the password must be a string');
  let raw;
  try {
    raw = Uint8Array.from(atob(ciphertext.trim()), (char) => char.charCodeAt(0));
  } catch {
    fail('ERR_INVALID_ARGUMENT', 'the encrypted secret is damaged or incomplete');
  }
  const data = raw.subarray(16);
  if (data.length === 0 || data.length % 16 !== 0) fail('ERR_INVALID_ARGUMENT', 'the encrypted secret is damaged or incomplete');

  const seed = concat(new TextEncoder().encode(password), raw.subarray(8, 16));
  const d1 = md5(seed);
  const d2 = md5(concat(d1, seed));
  const iv = md5(concat(d2, seed));
  const keyBytes = concat(d1, d2);
  try {
    const subtle = globalThis.crypto.subtle;
    const key = await subtle.importKey('raw', keyBytes, 'AES-CBC', false, ['decrypt']);
    const plain = await subtle.decrypt({ name: 'AES-CBC', iv }, key, data);
    return new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch {
    fail('ERR_WRONG_PASSWORD', 'wrong password');
  } finally {
    seed.fill(0);
    keyBytes.fill(0);
  }
}
