import { createHash } from 'node:crypto';

/** A reproducible byte source for tests: SHA-256 in counter mode. */
export function seededFill(seed) {
  let counter = 0;
  let pool = Buffer.alloc(0);
  return (bytes) => {
    while (pool.length < bytes.length) {
      pool = Buffer.concat([pool, createHash('sha256').update(`${seed}:${counter++}`).digest()]);
    }
    bytes.set(pool.subarray(0, bytes.length));
    pool = pool.subarray(bytes.length);
    return bytes;
  };
}

export const utf8 = (text) => new TextEncoder().encode(text);
export const fromHex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));
export const toHex = (bytes) => Buffer.from(bytes).toString('hex');

/** All k-element subsets of `items`. */
export function* subsets(items, k, start = 0, chosen = []) {
  if (chosen.length === k) { yield chosen; return; }
  for (let i = start; i < items.length; i++) yield* subsets(items, k, i + 1, [...chosen, items[i]]);
}
