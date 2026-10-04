import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { sha256 } from '../src/sha256.js';
import { toHex, utf8 } from './helpers.js';

test('SHA-256 matches the FIPS 180-4 example vectors', () => {
  assert.equal(toHex(sha256(utf8(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(toHex(sha256(utf8('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(
    toHex(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  );
  assert.equal(
    toHex(sha256(new Uint8Array(1_000_000).fill(0x61))),
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
  );
});

test('SHA-256 matches node:crypto at every length from 0 to 300', () => {
  for (let length = 0; length <= 300; length++) {
    const data = randomBytes(length);
    assert.equal(toHex(sha256(data)), createHash('sha256').update(data).digest('hex'), `length ${length}`);
  }
});

test('SHA-256 does not modify its input', () => {
  const data = randomBytes(100);
  const copy = Uint8Array.from(data);
  sha256(data);
  assert.deepEqual(Uint8Array.from(data), copy);
});
