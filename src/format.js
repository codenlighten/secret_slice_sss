// The ss1 share format. See docs/FORMAT.md for the specification.
//
//   text  = "ss1." base64url( share )
//   share = threshold(1) index(1) setId(8) body(n) checksum(4)

import { fail } from './errors.js';
import { sha256 } from './sha256.js';
import { encodeBase64url, decodeBase64url } from './base64url.js';

export const PREFIX = 'ss1.';
export const SET_ID_BYTES = 8;
export const DIGEST_BYTES = 16;
export const CHECKSUM_BYTES = 4;
export const HEADER_BYTES = 2 + SET_ID_BYTES;
export const MIN_BODY_BYTES = DIGEST_BYTES + 1;

const encoder = new TextEncoder();
const SHARE_DOMAIN = encoder.encode('secretslices/v1/share\0');
const SECRET_DOMAIN = encoder.encode('secretslices/v1/secret\0');

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function shareChecksum(bytes) {
  return sha256(concat(SHARE_DOMAIN, bytes)).subarray(0, CHECKSUM_BYTES);
}

/** The digest shared alongside the secret; it binds the threshold and set. */
export function secretDigest(threshold, setId, secret) {
  const input = concat(SECRET_DOMAIN, Uint8Array.of(threshold), setId, secret);
  const digest = sha256(input).slice(0, DIGEST_BYTES);
  input.fill(0);
  return digest;
}

export function hex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * @param {{threshold: number, index: number, setId: Uint8Array, body: Uint8Array}} share
 * @returns {string}
 */
export function encodeShare({ threshold, index, setId, body }) {
  const unchecked = concat(Uint8Array.of(threshold, index), setId, body);
  return PREFIX + encodeBase64url(concat(unchecked, shareChecksum(unchecked)));
}

/**
 * Parses and checks one ss1 share. Throws SecretSlicesError; never returns a
 * partially valid result.
 * @param {string} text
 * @returns {{threshold: number, index: number, setId: Uint8Array, body: Uint8Array}}
 */
export function decodeShare(text) {
  if (typeof text !== 'string') fail('ERR_INVALID_SHARE', 'a share must be a string');
  // Whitespace after the prefix carries no information: a share may be
  // written in groups. The prefix itself must be intact.
  const start = text.trim();
  const trimmed = start.slice(0, PREFIX.length) + start.slice(PREFIX.length).replace(/\s+/g, '');
  if (!trimmed.startsWith(PREFIX)) {
    const other = /^ss(\d+)\./.exec(trimmed);
    if (other) {
      fail('ERR_UNSUPPORTED_VERSION',
        `this share uses format version ${other[1]}, which this version of secretslices cannot read; upgrade secretslices`);
    }
    fail('ERR_INVALID_SHARE', 'not a SecretSlices share: it does not start with "ss1."');
  }
  const bytes = decodeBase64url(trimmed.slice(PREFIX.length));
  if (bytes.length < HEADER_BYTES + MIN_BODY_BYTES + CHECKSUM_BYTES) {
    fail('ERR_INVALID_SHARE', 'share is too short; it has probably been cut off');
  }
  const unchecked = bytes.subarray(0, bytes.length - CHECKSUM_BYTES);
  const expected = shareChecksum(unchecked);
  let difference = 0;
  for (let i = 0; i < CHECKSUM_BYTES; i++) difference |= expected[i] ^ bytes[unchecked.length + i];
  if (difference !== 0) {
    fail('ERR_SHARE_CHECKSUM', 'share checksum does not match; the share was mistyped, cut off or altered');
  }
  const threshold = bytes[0];
  const index = bytes[1];
  if (threshold < 2) fail('ERR_INVALID_SHARE', 'share has an invalid threshold');
  if (index < 1) fail('ERR_INVALID_SHARE', 'share has an invalid index');
  return {
    threshold,
    index,
    setId: bytes.slice(2, HEADER_BYTES),
    body: bytes.slice(HEADER_BYTES, unchecked.length),
  };
}
