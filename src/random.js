import { fail } from './errors.js';

/** Fills `bytes` from the platform's cryptographic random generator. */
export function randomFill(bytes) {
  const crypto = globalThis.crypto;
  if (!crypto || typeof crypto.getRandomValues !== 'function') {
    fail('ERR_NO_RANDOM', 'no cryptographic random generator (crypto.getRandomValues) is available');
  }
  // getRandomValues accepts at most 65536 bytes per call.
  for (let offset = 0; offset < bytes.length; offset += 65536) {
    crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65536, bytes.length)));
  }
  return bytes;
}
