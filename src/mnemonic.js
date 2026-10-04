// BIP-39 mnemonic phrases (English), for generating a fresh secret to split
// and for checking a phrase before it is split.

import { fail } from './errors.js';
import { randomFill } from './random.js';
import { sha256 } from './sha256.js';
import { ENGLISH } from './bip39-english.js';

const WORD_COUNTS = [12, 15, 18, 21, 24];

/**
 * @param {Uint8Array} entropy 16, 20, 24, 28 or 32 bytes
 * @returns {string} the phrase, words separated by single spaces
 */
export function entropyToMnemonic(entropy) {
  if (!(entropy instanceof Uint8Array) || entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) {
    fail('ERR_INVALID_ARGUMENT', 'entropy must be 16, 20, 24, 28 or 32 bytes');
  }
  const checksumBits = entropy.length / 4;
  const bytes = [...entropy, sha256(entropy)[0]];
  const words = [];
  let buffer = 0;
  let bits = 0;
  let produced = 0;
  const total = entropy.length * 8 + checksumBits;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 11 && produced + 11 <= total) {
      bits -= 11;
      words.push(ENGLISH[(buffer >>> bits) & 0x7ff]);
      buffer &= (1 << bits) - 1;
      produced += 11;
    }
  }
  return words.join(' ');
}

/**
 * @param {12 | 15 | 18 | 21 | 24} [words]
 * @returns {string} a new random phrase
 */
export function generateMnemonic(words = 12) {
  if (!WORD_COUNTS.includes(words)) fail('ERR_INVALID_ARGUMENT', 'words must be 12, 15, 18, 21 or 24');
  const entropy = randomFill(new Uint8Array((words * 4) / 3));
  const phrase = entropyToMnemonic(entropy);
  entropy.fill(0);
  return phrase;
}

/**
 * @param {string} phrase
 * @returns {boolean} true if the phrase is a BIP-39 English mnemonic with a correct checksum
 */
export function validateMnemonic(phrase) {
  if (typeof phrase !== 'string') return false;
  const words = phrase.trim().split(/\s+/);
  if (!WORD_COUNTS.includes(words.length)) return false;
  const entropy = new Uint8Array((words.length * 4) / 3);
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (const word of words) {
    const index = ENGLISH.indexOf(word);
    if (index < 0) return false;
    buffer = (buffer << 11) | index;
    bits += 11;
    while (bits >= 8 && o < entropy.length) {
      bits -= 8;
      entropy[o++] = (buffer >>> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  const checksumBits = entropy.length / 4;
  const valid = buffer === sha256(entropy)[0] >>> (8 - checksumBits);
  entropy.fill(0);
  return valid;
}
