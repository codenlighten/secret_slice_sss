import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { ENGLISH } from '../src/bip39-english.js';
import { entropyToMnemonic, generateMnemonic, validateMnemonic } from '../src/mnemonic.js';
import { fromHex } from './helpers.js';

// From the BIP-39 reference test vectors (trezor/python-mnemonic vectors.json).
const VECTORS = [
  ['00000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'],
  ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow'],
  ['80808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'],
  ['ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'],
  ['000000000000000000000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent'],
  ['808080808080808080808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always'],
  ['0000000000000000000000000000000000000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'],
  ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title'],
  ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote'],
  ['9e885d952ad362caeb4efe34a8e91bd2', 'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic'],
];

test('the word list is the published BIP-39 English list', () => {
  assert.equal(ENGLISH.length, 2048);
  assert.equal(
    createHash('sha256').update(`${ENGLISH.join('\n')}\n`).digest('hex'),
    '2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda',
  );
});

test('BIP-39 reference vectors', () => {
  for (const [entropy, phrase] of VECTORS) {
    assert.equal(entropyToMnemonic(fromHex(entropy)), phrase);
    assert.equal(validateMnemonic(phrase), true);
  }
});

test('generated phrases are valid, of the right length, and different each time', () => {
  for (const words of [12, 15, 18, 21, 24]) {
    const phrases = Array.from({ length: 20 }, () => generateMnemonic(words));
    for (const phrase of phrases) {
      assert.equal(phrase.split(' ').length, words);
      assert.equal(validateMnemonic(phrase), true);
    }
    assert.equal(new Set(phrases).size, 20);
  }
  assert.equal(generateMnemonic().split(' ').length, 12);
  for (const bad of [0, 11, 13, 25, '12', 12.5]) assert.throws(() => generateMnemonic(bad), { code: 'ERR_INVALID_ARGUMENT' });
});

test('invalid phrases are rejected', () => {
  const good = VECTORS[1][1];
  assert.equal(validateMnemonic(good.replace('yellow', 'year')), false, 'wrong checksum');
  assert.equal(validateMnemonic(good.replace('legal', 'legall')), false, 'unknown word');
  assert.equal(validateMnemonic(good.split(' ').slice(0, 11).join(' ')), false, 'eleven words');
  assert.equal(validateMnemonic(`${good} zoo`), false);
  assert.equal(validateMnemonic(good.toUpperCase()), false);
  assert.equal(validateMnemonic(''), false);
  assert.equal(validateMnemonic(null), false);
  assert.equal(validateMnemonic(`  ${good.replace(/ /g, '   ')}\n`), true, 'extra whitespace is tolerated');
  for (const length of [0, 15, 17, 33, 36]) {
    assert.throws(() => entropyToMnemonic(new Uint8Array(length)), { code: 'ERR_INVALID_ARGUMENT' });
  }
  assert.throws(() => entropyToMnemonic('0'.repeat(16)), { code: 'ERR_INVALID_ARGUMENT' });
});
