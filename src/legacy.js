// Read-only support for every share format that SecretSlices has shipped or
// been built on. These formats carry no integrity check, so a wrong or
// insufficient set of shares can only be detected indirectly; new shares are
// always written in the ss1 format.
//
//   "secrets.js"  secretslices.com browser app (2024): hex strings such as
//                 "801f4a...", usually wrapped as {"part": 1, "value": "801f4a..."}
//   "shamir"      secretslices.com server API (2024), `shamir` npm package:
//                 {"part": "1", "value": "12,240,7,..."}
//   "sssa"        SSSaaS/sssa-js and its ports: base64url blocks of 88 characters

import { fail } from './errors.js';
import { AES, RS, interpolateAtZero } from './gf256.js';

export const LEGACY_FORMATS = Object.freeze(['secrets.js', 'shamir', 'sssa']);

const SECRETS_JS = /^[0-9a-z][0-9a-f]{2}[0-9a-f]+$/i;
const SHAMIR_BYTES = /^\d{1,3}(,\d{1,3})*$/;
const SSSA = /^(?:[A-Za-z0-9_\-+/]{43}=){2,}$/;

function sameBytes(a, b) {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}

// ---------------------------------------------------------------- secrets.js

function parseSecretsJs(text) {
  const bits = parseInt(text[0], 36);
  if (bits !== 8) {
    fail('ERR_UNSUPPORTED_VERSION', `secrets.js share uses ${bits}-bit fields; only the default 8-bit shares are supported`);
  }
  const id = parseInt(text.slice(1, 3), 16);
  if (id < 1) fail('ERR_INVALID_SHARE', 'secrets.js share has an invalid id');
  const digits = text.slice(3);
  if (digits.length % 2 !== 0) fail('ERR_INVALID_SHARE', 'secrets.js share has an odd number of hex digits');
  const y = new Uint8Array(digits.length / 2);
  for (let i = 0; i < y.length; i++) y[i] = parseInt(digits.slice(i * 2, i * 2 + 2), 16);
  return { format: 'secrets.js', x: id, y };
}

function combineSecretsJs(xs, ys) {
  // The shared value is the bit string "1" + secret, zero-padded on the left,
  // so the bytes are: zeros, one 0x01 marker byte, then the secret.
  const value = interpolateAtZero(xs, ys, RS);
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  if (start === value.length || value[start] !== 0x01) {
    fail('ERR_INTEGRITY', 'the shares do not reconstruct a valid secret: some are wrong, or too few were given');
  }
  return value.slice(start + 1);
}

// -------------------------------------------------------------------- shamir

function parseShamir(part, value) {
  const x = Number(part);
  if (!Number.isInteger(x) || x < 1 || x > 255) fail('ERR_INVALID_SHARE', `share has an invalid part number: ${String(part)}`);
  const y = Uint8Array.from(value.split(','), (text) => {
    const byte = Number(text);
    if (byte > 255) fail('ERR_INVALID_SHARE', 'share contains a value that is not a byte');
    return byte;
  });
  return { format: 'shamir', x, y };
}

// ---------------------------------------------------------------------- sssa

const P = 2n ** 256n - 189n;
const mod = (n) => ((n % P) + P) % P;

function inverse(n) {
  // Extended Euclid; n is non-zero modulo the prime P.
  let [r0, r1, t0, t1] = [P, mod(n), 0n, 1n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  return mod(t0);
}

function sssaNumber(text) {
  const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let n = 0n;
  for (const char of text.slice(0, 43).replace(/\+/g, '-').replace(/\//g, '_')) n = (n << 6n) | BigInt(BASE64.indexOf(char));
  return n >> 2n; // 43 characters carry 258 bits; the value is the top 256
}

function parseSssa(text) {
  const blocks = [];
  for (let offset = 0; offset < text.length; offset += 88) {
    const x = mod(sssaNumber(text.slice(offset, offset + 44)));
    if (x === 0n) fail('ERR_INVALID_SHARE', 'sssa share has a zero x coordinate');
    blocks.push([x, mod(sssaNumber(text.slice(offset + 44, offset + 88)))]);
  }
  return { format: 'sssa', blocks, text };
}

function combineSssa(shares) {
  const blockCount = shares[0].blocks.length;
  const out = new Uint8Array(blockCount * 32);
  for (let b = 0; b < blockCount; b++) {
    const points = shares.map((share) => share.blocks[b]);
    let secret = 0n;
    points.forEach(([xi, yi], i) => {
      let numerator = 1n;
      let denominator = 1n;
      points.forEach(([xj], j) => {
        if (j === i) return;
        if (xj === xi) fail('ERR_DUPLICATE_SHARE', 'two sssa shares have the same x coordinate');
        numerator = mod(numerator * -xj);
        denominator = mod(denominator * (xi - xj));
      });
      secret = mod(secret + yi * numerator * inverse(denominator));
    });
    for (let i = 31; i >= 0; i--) {
      out[b * 32 + i] = Number(secret & 0xffn);
      secret >>= 8n;
    }
  }
  // The format pads the last block with zero bytes and records no length.
  let end = out.length;
  while (end > 0 && out[end - 1] === 0) end--;
  return out.slice(0, end);
}

/**
 * sssa-js wrote characters outside the Basic Multilingual Plane (emoji, for
 * example) as two 3-byte surrogate sequences (CESU-8) where UTF-8 uses one
 * 4-byte sequence; its Go counterpart wrote UTF-8. This rewrites the former
 * as the latter, so one strict UTF-8 decoder reads both.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function cesu8ToUtf8(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i++) {
    const pair = bytes[i] === 0xed && (bytes[i + 1] & 0xf0) === 0xa0 && (bytes[i + 2] & 0xc0) === 0x80
      && bytes[i + 3] === 0xed && (bytes[i + 4] & 0xf0) === 0xb0 && (bytes[i + 5] & 0xc0) === 0x80;
    if (!pair) {
      out.push(bytes[i]);
      continue;
    }
    const high = ((bytes[i + 1] & 0x0f) << 6) | (bytes[i + 2] & 0x3f);
    const low = ((bytes[i + 4] & 0x0f) << 6) | (bytes[i + 5] & 0x3f);
    const point = 0x10000 + ((high << 10) | low);
    out.push(0xf0 | (point >> 18), 0x80 | ((point >> 12) & 0x3f), 0x80 | ((point >> 6) & 0x3f), 0x80 | (point & 0x3f));
    i += 5;
  }
  return Uint8Array.from(out);
}

// ------------------------------------------------------------------- general

/**
 * Recognises one legacy share.
 * @param {string | {part?: unknown, value?: unknown}} item
 * @returns {object | null} the parsed share, or null if it is not a legacy share
 */
export function parseLegacyShare(item) {
  let part;
  let value = item;
  if (item !== null && typeof item === 'object') ({ part, value } = item);
  if (typeof value !== 'string') return null;
  value = value.trim();
  if (SHAMIR_BYTES.test(value) && part !== undefined) return parseShamir(part, value);
  if (SSSA.test(value)) return parseSssa(value);
  if (SECRETS_JS.test(value)) return parseSecretsJs(value);
  return null;
}

/**
 * Combines parsed legacy shares of one format.
 * @param {object[]} shares results of parseLegacyShare
 * @returns {Uint8Array} the secret bytes (unverified)
 */
export function combineLegacyShares(shares) {
  const format = shares[0].format;
  if (shares.some((share) => share.format !== format)) {
    fail('ERR_MIXED_SHARES', 'the shares are in different formats');
  }

  let distinct;
  if (format === 'sssa') {
    distinct = [...new Map(shares.map((share) => [share.text, share])).values()];
    if (distinct.some((share) => share.blocks.length !== distinct[0].blocks.length)) {
      fail('ERR_MIXED_SHARES', 'the shares have different lengths, so they come from different secrets');
    }
  } else {
    const byX = new Map();
    shares.forEach((share, position) => {
      if (share.y.length !== shares[0].y.length) {
        fail('ERR_MIXED_SHARES', `share ${position + 1} has a different length from share 1, so they come from different secrets`, { shareIndex: position });
      }
      const seen = byX.get(share.x);
      if (seen === undefined) byX.set(share.x, share);
      else if (!sameBytes(seen.y, share.y)) {
        fail('ERR_DUPLICATE_SHARE', `share ${position + 1} has the same number as an earlier share but different contents`, { shareIndex: position });
      }
    });
    distinct = [...byX.values()];
  }

  if (distinct.length < 2) {
    fail('ERR_INSUFFICIENT_SHARES', 'at least 2 different shares are needed', { required: 2, provided: distinct.length });
  }
  if (format === 'sssa') return combineSssa(distinct);
  const xs = distinct.map((share) => share.x);
  const ys = distinct.map((share) => share.y);
  return format === 'secrets.js' ? combineSecretsJs(xs, ys) : interpolateAtZero(xs, ys, AES);
}
