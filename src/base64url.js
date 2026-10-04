import { fail } from './errors.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const VALUES = new Int8Array(128).fill(-1);
for (let i = 0; i < 64; i++) VALUES[ALPHABET.charCodeAt(i)] = i;

/** Unpadded base64url (RFC 4648 section 5). */
export function encodeBase64url(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63] + ALPHABET[(n >>> 6) & 63] + ALPHABET[n & 63];
  }
  if (i + 1 === bytes.length) {
    const n = bytes[i] << 16;
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63];
  } else if (i + 2 === bytes.length) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63] + ALPHABET[(n >>> 6) & 63];
  }
  return out;
}

/**
 * Decodes unpadded base64url. With `strict` (the default) a text that is not
 * the canonical encoding of its bytes is rejected, so one byte string has
 * exactly one accepted spelling.
 */
export function decodeBase64url(text, strict = true) {
  const tail = text.length % 4;
  if (tail === 1) fail('ERR_INVALID_SHARE', 'not valid base64url: impossible length');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? VALUES[code] : -1;
    if (value < 0) fail('ERR_INVALID_SHARE', `not valid base64url: unexpected character at position ${i + 1}`);
    buffer = ((buffer << 6) | value) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >>> bits) & 0xff;
    }
  }
  if (strict && (buffer & ((1 << bits) - 1)) !== 0) {
    fail('ERR_INVALID_SHARE', 'not valid base64url: non-canonical final character');
  }
  return out;
}
