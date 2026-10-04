import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SecretSlicesError, recover, split, validate } from '../src/index.js';
import { splitWith } from '../src/core.js';
import { seededFill } from './helpers.js';

const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy.json', import.meta.url), 'utf8'));

// A reproducible stream of random numbers for mutation testing.
function generator(seed) {
  const fill = seededFill(seed);
  const buffer = new Uint8Array(4);
  return (limit) => {
    fill(buffer);
    return new DataView(buffer.buffer).getUint32(0) % limit;
  };
}

function mutate(text, random) {
  const alphabet = 'ABCxyz019-_=+/.,:"{}[] \né😀';
  const position = random(text.length + 1);
  switch (random(5)) {
    case 0: return text.slice(0, position) + alphabet[random(alphabet.length)] + text.slice(position + 1);
    case 1: return text.slice(0, position) + text.slice(position + 1 + random(4));
    case 2: return text.slice(0, position) + alphabet[random(alphabet.length)] + text.slice(position);
    case 3: return text.slice(0, position);
    default: return text.slice(position) + text.slice(0, position);
  }
}

test('validate() never throws, whatever it is given', () => {
  const oddities = [
    undefined, null, true, 0, -1, NaN, 1n, Symbol('s'), () => {}, {}, [], [[]], new Date(), new Uint8Array(3),
    '', ' ', 'ss1.', 'ss1', 'ss0.AAAA', 'ss99.AAAA', '.', '8', '80', '801', '8011', '=', '='.repeat(88),
    { value: null }, { part: {}, value: '1,2' }, { part: 1, value: {} }, { get value() { throw new Error('getter'); } },
    'a'.repeat(100_000), 'ss1.' + 'A'.repeat(100_000), '8' + '0'.repeat(100_001),
  ];
  for (const input of oddities) {
    const result = validate(input);
    assert.equal(result.valid, false, typeof input);
    assert.equal(typeof result.code, 'string');
    assert.equal(typeof result.message, 'string');
  }
});

test('20000 mutated shares: recover() either succeeds with the right secret or throws a SecretSlicesError', () => {
  const random = generator('mutation');
  const secret = 'the one true secret';
  const sets = [
    splitWith(seededFill('mutation-ss1'), secret, { shares: 3, threshold: 2 }),
    ...['secrets.js', 'shamir', 'sssa'].map((format) => legacy.find((f) => f.format === format && f.threshold === 2 && f.shares.length === 3 && f.text.length > 40).shares
      .map((share) => (typeof share === 'string' ? share : JSON.stringify(share)))),
  ];
  let failures = 0;
  let wrong = 0;
  for (let round = 0; round < 20000; round++) {
    const set = sets[round % sets.length];
    const isSs1 = round % sets.length === 0;
    const mutated = mutate(set[0], random);
    assert.doesNotThrow(() => validate(mutated));
    try {
      const result = recover([mutated, set[1]]);
      if (isSs1) {
        // The verified format must never return anything but the secret.
        assert.equal(result.text(), secret, `mutation ${JSON.stringify(mutated)} returned a different secret`);
      } else {
        wrong++;
      }
    } catch (error) {
      assert.ok(error instanceof SecretSlicesError, `round ${round}: ${error?.stack}`);
      failures++;
    }
  }
  assert.ok(failures > 10000);
  assert.ok(wrong > 0, 'the legacy formats cannot detect every mutation; that is why they are read-only');
});

test('random text is never mistaken for a set of shares', () => {
  const random = generator('garbage');
  const alphabet = 'abcdef0123456789ABCXYZ-_=.,{}[]":\n ';
  for (let round = 0; round < 3000; round++) {
    let text = '';
    for (let i = random(120); i > 0; i--) text += alphabet[random(alphabet.length)];
    try {
      const result = recover(text);
      assert.notEqual(result.format, 'ss1', `garbage accepted as ss1: ${JSON.stringify(text)}`);
    } catch (error) {
      assert.ok(error instanceof SecretSlicesError, `${JSON.stringify(text)}: ${error?.stack}`);
    }
  }
});

test('errors are real Errors with a stable shape', () => {
  try {
    split('s', { shares: 1, threshold: 1 });
    assert.fail('should have thrown');
  } catch (error) {
    assert.ok(error instanceof Error && error instanceof SecretSlicesError);
    assert.equal(error.name, 'SecretSlicesError');
    assert.equal(error.code, 'ERR_INVALID_ARGUMENT');
    assert.ok(error.stack.includes('SecretSlicesError'));
  }
});
