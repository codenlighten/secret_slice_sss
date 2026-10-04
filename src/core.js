// Splitting and combining for the ss1 format: Shamir's scheme over GF(2^8),
// applied to every byte of digest || secret || padding with independent
// random polynomials.

import { fail } from './errors.js';
import { AES, hornerStep, interpolateAtZero, packed } from './gf256.js';
import {
  DIGEST_BYTES, MIN_BODY_BYTES, SET_ID_BYTES, decodeShare, encodeShare, hex, secretDigest,
} from './format.js';

const encoder = new TextEncoder();
const LONE_SURROGATE = /\p{Surrogate}/u;

export const MAX_SHARES = 255;
export const MAX_PAD_TO = 65536;

function integerOption(name, value, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    fail('ERR_INVALID_ARGUMENT', `${name} must be an integer from ${min} to ${max}, got ${String(value)}`);
  }
  return value;
}

/** Normalises a secret to bytes. Strings are encoded as UTF-8. */
export function secretBytes(secret) {
  if (typeof secret === 'string') {
    if (LONE_SURROGATE.test(secret)) {
      fail('ERR_INVALID_ARGUMENT', 'the secret string contains an unpaired surrogate and cannot be encoded as UTF-8');
    }
    return encoder.encode(secret);
  }
  if (secret instanceof Uint8Array) return Uint8Array.from(secret);
  fail('ERR_INVALID_ARGUMENT', 'the secret must be a string or a Uint8Array');
}

/**
 * Splits a secret. `fill` supplies the randomness, so tests can make the
 * output reproducible; the public API always passes the platform generator.
 * @param {(bytes: Uint8Array) => unknown} fill
 * @param {string | Uint8Array} secret
 * @param {{shares: number, threshold: number, padTo?: number}} options
 * @returns {string[]}
 */
export function splitWith(fill, secret, options) {
  if (options === null || typeof options !== 'object') {
    fail('ERR_INVALID_ARGUMENT', 'options must be an object: { shares, threshold }');
  }
  const shares = integerOption('shares', options.shares, 2, MAX_SHARES);
  const threshold = integerOption('threshold', options.threshold, 2, MAX_SHARES);
  if (threshold > shares) {
    fail('ERR_INVALID_ARGUMENT', `threshold (${threshold}) cannot be greater than shares (${shares})`);
  }
  const padTo = integerOption('padTo', options.padTo ?? 1, 1, MAX_PAD_TO);
  const bytes = secretBytes(secret);

  const setId = new Uint8Array(SET_ID_BYTES);
  fill(setId);

  // payload = digest || secret || 0x80 || 0x00...   (ISO/IEC 7816-4 padding)
  const paddedLength = Math.ceil((bytes.length + 1) / padTo) * padTo;
  const length = DIGEST_BYTES + paddedLength;
  const payload = packed(length);
  payload.bytes.set(secretDigest(threshold, setId, bytes));
  payload.bytes.set(bytes, DIGEST_BYTES);
  payload.bytes[DIGEST_BYTES + bytes.length] = 0x80;
  bytes.fill(0);

  // coefficients[j] holds the coefficient of x^(j+1) for every payload byte.
  // They are uniform over the whole field, zero included: forcing the top
  // coefficient to be non-zero would leak information.
  const coefficients = [];
  for (let j = 1; j < threshold; j++) {
    const coefficient = packed(length);
    fill(coefficient.bytes);
    coefficients.push(coefficient.words);
  }

  const result = [];
  const acc = packed(length);
  for (let index = 1; index <= shares; index++) {
    acc.words.set(coefficients[threshold - 2]);
    for (let j = threshold - 3; j >= 0; j--) hornerStep(acc.words, index, coefficients[j], AES);
    hornerStep(acc.words, index, payload.words, AES);
    result.push(encodeShare({ threshold, index, setId, body: acc.bytes.subarray(0, length) }));
  }

  acc.words.fill(0);
  payload.words.fill(0);
  for (const coefficient of coefficients) coefficient.fill(0);
  return result;
}

/**
 * Decodes ss1 shares and checks that they belong together.
 * @param {string[]} texts
 * @returns {{threshold: number, setId: Uint8Array, shares: {index: number, body: Uint8Array}[]}}
 */
export function decodeSet(texts) {
  if (texts.length === 0) fail('ERR_INVALID_ARGUMENT', 'no shares were given');
  const byIndex = new Map();
  let first;
  texts.forEach((text, position) => {
    let share;
    try {
      share = decodeShare(text);
    } catch (error) {
      error.message = `share ${position + 1}: ${error.message}`;
      error.shareIndex = position;
      throw error;
    }
    first ??= share;
    if (hex(share.setId) !== hex(first.setId)) {
      fail('ERR_MIXED_SHARES', `share ${position + 1} comes from a different split than share 1`, { shareIndex: position });
    }
    if (share.threshold !== first.threshold || share.body.length !== first.body.length) {
      fail('ERR_MIXED_SHARES', `share ${position + 1} is inconsistent with share 1`, { shareIndex: position });
    }
    const seen = byIndex.get(share.index);
    if (seen === undefined) {
      byIndex.set(share.index, share);
    } else if (hex(seen.body) !== hex(share.body)) {
      fail('ERR_DUPLICATE_SHARE', `share ${position + 1} has the same index as an earlier share but different contents`, { shareIndex: position });
    }
    // An exact repeat of an earlier share is ignored.
  });
  return { threshold: first.threshold, setId: first.setId, shares: [...byIndex.values()] };
}

/**
 * Recombines ss1 shares and verifies the result.
 * @param {string[]} texts
 * @returns {Uint8Array} the secret
 */
export function combineSet(texts) {
  const { threshold, setId, shares } = decodeSet(texts);
  if (shares.length < threshold) {
    fail('ERR_INSUFFICIENT_SHARES',
      `this secret needs ${threshold} different shares, but only ${shares.length} ${shares.length === 1 ? 'was' : 'were'} given`,
      { required: threshold, provided: shares.length });
  }
  const payload = interpolateAtZero(shares.map((s) => s.index), shares.map((s) => s.body), AES);

  let end = payload.length - 1;
  while (end >= DIGEST_BYTES && payload[end] === 0) end--;
  let valid = end >= DIGEST_BYTES && payload[end] === 0x80 && payload.length >= MIN_BODY_BYTES;
  const secret = valid ? payload.slice(DIGEST_BYTES, end) : new Uint8Array(0);
  if (valid) {
    const expected = secretDigest(threshold, setId, secret);
    let difference = 0;
    for (let i = 0; i < DIGEST_BYTES; i++) difference |= expected[i] ^ payload[i];
    valid = difference === 0;
  }
  payload.fill(0);
  if (!valid) {
    secret.fill(0);
    fail('ERR_INTEGRITY', 'the shares do not reconstruct a valid secret: at least one share has been altered or does not belong to this set');
  }
  return secret;
}
