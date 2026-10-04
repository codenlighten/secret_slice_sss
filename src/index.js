import { SecretSlicesError, fail } from './errors.js';
import { randomFill } from './random.js';
import { combineSet, splitWith } from './core.js';
import { DIGEST_BYTES, PREFIX, decodeShare, hex } from './format.js';
import { collectShares } from './input.js';
import { cesu8ToUtf8, combineLegacyShares, parseLegacyShare } from './legacy.js';

export { SecretSlicesError };

/** Every share format this version can read. New shares are always "ss1". */
export const FORMATS = Object.freeze(['ss1', 'secrets.js', 'shamir', 'sssa']);

function decodeText(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('ERR_INVALID_UTF8', 'the recovered secret is not valid UTF-8 text; it is binary data, or the shares are wrong');
  }
}

function isSs1(item) {
  return typeof item === 'string' && /^ss\d+\./.test(item.trim());
}

/**
 * Splits a secret into shares. Any `threshold` of them recover it; fewer
 * reveal nothing about it except an upper bound on its length.
 * @param {string | Uint8Array} secret text (stored as UTF-8) or bytes
 * @param {{shares: number, threshold: number, padTo?: number}} options
 * @returns {string[]} `shares` strings starting with "ss1."
 */
export function split(secret, options) {
  return splitWith(randomFill, secret, options);
}

/**
 * Recovers a secret from ss1 shares and verifies it.
 * @param {Iterable<string>} shares at least `threshold` shares, in any order
 * @returns {Uint8Array}
 */
export function combine(shares) {
  if (shares === null || shares === undefined || typeof shares === 'string' || typeof shares[Symbol.iterator] !== 'function') {
    fail('ERR_INVALID_ARGUMENT', 'shares must be an array of share strings');
  }
  return combineSet([...shares]);
}

/** Like combine(), for a secret that was given to split() as a string. */
export function combineText(shares) {
  return decodeText(combine(shares));
}

/**
 * Recovers a secret from shares in ANY format SecretSlices has ever produced,
 * given as an array, as pasted text, or as the contents of share files.
 * @param {unknown} input
 * @returns {{secret: Uint8Array, format: string, verified: boolean, text: () => string}}
 *   `verified` is true only for ss1, the one format that can prove the
 *   result is the original secret.
 */
export function recover(input) {
  const items = collectShares(input);
  let secret;
  let format;
  if (items.some(isSs1)) {
    if (!items.every(isSs1)) fail('ERR_MIXED_SHARES', 'the shares are in different formats');
    secret = combineSet(items);
    format = 'ss1';
  } else {
    const parsed = items.map((item, position) => {
      const share = parseLegacyShare(item);
      if (share === null) fail('ERR_INVALID_SHARE', `share ${position + 1} is not in a recognised format`, { shareIndex: position });
      return share;
    });
    secret = combineLegacyShares(parsed);
    format = parsed[0].format;
  }
  return {
    secret,
    format,
    verified: format === 'ss1',
    text: () => decodeText(format === 'sssa' ? cesu8ToUtf8(secret) : secret),
  };
}

/**
 * Describes one ss1 share without needing the others.
 * @param {string} share
 * @returns {{format: 'ss1', threshold: number, index: number, setId: string, maxSecretBytes: number}}
 */
export function inspect(share) {
  const { threshold, index, setId, body } = decodeShare(share);
  return { format: 'ss1', threshold, index, setId: hex(setId), maxSecretBytes: body.length - DIGEST_BYTES - 1 };
}

/**
 * Checks one share in any supported format. Never throws.
 * @param {unknown} share a share string or a legacy {part, value} object
 * @returns {{valid: true, format: string, threshold?: number, index?: number, setId?: string}
 *   | {valid: false, code: string, message: string}}
 */
export function validate(share) {
  try {
    if (isSs1(share)) {
      const { threshold, index, setId } = inspect(share);
      return { valid: true, format: 'ss1', threshold, index, setId };
    }
    const legacy = parseLegacyShare(share);
    if (legacy === null) {
      return { valid: false, code: 'ERR_INVALID_SHARE', message: `not a share in any supported format (new shares start with "${PREFIX}")` };
    }
    return legacy.format === 'sssa' ? { valid: true, format: 'sssa' } : { valid: true, format: legacy.format, index: legacy.x };
  } catch (error) {
    return {
      valid: false,
      code: error instanceof SecretSlicesError ? error.code : 'ERR_INVALID_SHARE',
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
