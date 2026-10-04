import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { decodeBase64url, encodeBase64url } from '../src/base64url.js';
import { SecretSlicesError } from '../src/errors.js';

test('encoding matches Node at every length from 0 to 100', () => {
  for (let length = 0; length <= 100; length++) {
    const data = randomBytes(length);
    const text = encodeBase64url(data);
    assert.equal(text, data.toString('base64url'));
    assert.deepEqual(decodeBase64url(text), Uint8Array.from(data));
  }
});

test('decoding rejects anything but the canonical spelling', () => {
  const invalid = (text) => assert.throws(() => decodeBase64url(text), (e) => e instanceof SecretSlicesError && e.code === 'ERR_INVALID_SHARE');
  invalid('A');          // impossible length
  invalid('AAAAA');
  invalid('AA==');       // padding is not used
  invalid('AA+A');       // standard-alphabet characters
  invalid('AA/A');
  invalid('AA A');
  invalid('AAé');
  invalid('AB');         // unused bits set: same bytes as "AA"
  invalid('AAB');
  assert.deepEqual(decodeBase64url('AB', false), Uint8Array.of(0));
  assert.deepEqual(decodeBase64url(''), new Uint8Array(0));
});
