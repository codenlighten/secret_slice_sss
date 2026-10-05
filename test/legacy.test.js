// Every legacy fixture was written by the ORIGINAL encoder (see
// scripts/make-fixtures.mjs), so these tests check the decoders against what
// really shipped, not against this library's idea of it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { FORMATS, SecretSlicesError, combine, recover, split, validate } from '../src/index.js';
import * as legacyModule from '../src/legacy.js';
import { LEGACY_FORMATS, combineLegacyShares, parseLegacyShare } from '../src/legacy.js';
import { subsets } from './helpers.js';

const fixtures = JSON.parse(readFileSync(new URL('./fixtures/legacy.json', import.meta.url), 'utf8'));
const code = (expected) => (error) => {
  assert.ok(error instanceof SecretSlicesError, `expected a SecretSlicesError, got ${error}`);
  assert.equal(error.code, expected, error.message);
  return true;
};
const first = (format, minShares = 3) => fixtures.find((f) => f.format === format && f.shares.length >= minShares && f.threshold === 2 && f.text.length > 20);

test('the fixtures cover every encoder that shipped', () => {
  const encoders = new Set(fixtures.map((f) => f.encoder));
  assert.equal(encoders.size, 5);
  assert.deepEqual([...new Set(fixtures.map((f) => f.format))].sort(), [...LEGACY_FORMATS].sort());
  assert.deepEqual(FORMATS, ['ss1', ...LEGACY_FORMATS]);
});

for (const encoder of new Set(fixtures.map((f) => f.encoder))) {
  test(`recovers shares written by ${encoder}`, () => {
    for (const fixture of fixtures.filter((f) => f.encoder === encoder)) {
      const label = `${JSON.stringify(fixture.text.slice(0, 20))} ${fixture.threshold}-of-${fixture.shares.length}`;
      let count = 0;
      for (const subset of subsets(fixture.shares, fixture.threshold)) {
        if (count++ >= 12) break;
        const result = recover(subset);
        assert.equal(result.text(), fixture.text, label);
        assert.equal(result.format, fixture.format);
        assert.equal(result.verified, false);
      }
      assert.equal(recover([...fixture.shares].reverse()).text(), fixture.text, `${label}, all shares reversed`);
      for (const share of fixture.shares) assert.equal(validate(share).format, fixture.format);
    }
  });
}

test('recover accepts shares the way people actually hand them over', () => {
  const browser = first('secrets.js');
  assert.equal(typeof browser.shares[0], 'object', 'fixture is the {part, value} form');
  const two = browser.shares.slice(0, 2);
  // the recovery box of the 2024 app: a JSON array
  assert.equal(recover(JSON.stringify(two)).text(), browser.text);
  // the contents of downloaded part-N.json files, pasted one after another
  assert.equal(recover(two.map((s) => JSON.stringify(s)).join('\n')).text(), browser.text);
  assert.equal(recover(two.map((s) => JSON.stringify(s, null, 2)).join('\n\n')).text(), browser.text);
  // one file's contents per array element
  assert.equal(recover(two.map((s) => JSON.stringify(s))).text(), browser.text);
  // just the values
  assert.equal(recover(two.map((s) => s.value)).text(), browser.text);
  assert.equal(recover(two.map((s) => s.value).join('  \n')).text(), browser.text);
  assert.equal(recover(two.map((s) => s.value.toUpperCase())).text(), browser.text, 'hex case does not matter');

  const server = first('shamir');
  assert.equal(recover(JSON.stringify(server.shares.slice(1, 3))).text(), server.text);
  assert.equal(recover(server.shares.slice(1, 3).map((s) => ({ part: Number(s.part), value: s.value }))).text(), server.text);

  const sssa = first('sssa');
  assert.equal(recover(sssa.shares.slice(0, 2).join('\n')).text(), sssa.text);
  assert.equal(recover(JSON.stringify(sssa.shares.slice(0, 2))).text(), sssa.text);

  const ss1 = split('new format', { shares: 3, threshold: 2 });
  assert.equal(recover(ss1.join('\n')).text(), 'new format');
  assert.equal(recover(JSON.stringify(ss1)).text(), 'new format');
  assert.equal(recover(`"${ss1[0]}",\n"${ss1[2]}"`).text(), 'new format');
  assert.equal(recover(ss1.map((share) => ({ share }))).text(), 'new format');
  assert.equal(recover(ss1).verified, true);
});

test('nothing in pasted text is silently skipped', () => {
  const { shares, text } = first('shamir');
  const [a, b] = shares.map((share) => JSON.stringify(share));
  const [ss1] = split('x', { shares: 2, threshold: 2 });
  assert.equal(recover(`${a}\n${b}`).text(), text);
  assert.throws(() => recover(`${a}\n${b}\n${ss1}`), code('ERR_MIXED_SHARES'), 'a trailing share of another format');
  assert.throws(() => recover(`${ss1}\n${a}\n${b}`), code('ERR_MIXED_SHARES'), 'a leading share of another format');
  assert.throws(() => recover(`${a}\nstray words\n${b}`), code('ERR_INVALID_SHARE'), 'text between the objects');
  assert.throws(() => recover(`${a}\n${b}\nss1.invalid`), SecretSlicesError);
  assert.equal(recover(`[${a},\n${b}`).text(), text, 'a JSON array missing its closing bracket');
  const pair = split('nested', { shares: 2, threshold: 2 });
  assert.equal(recover(`${pair[0]}\n${JSON.stringify({ share: pair[1], meta: { note: 'a } brace { in a "string"' } })}`).text(), 'nested', 'objects with nested fields');
  assert.throws(() => recover(`${a}\n{"part": 2, "value": "1,2"`), code('ERR_INVALID_SHARE'), 'an object that never closes');
});

test('repeated legacy shares are ignored; conflicting ones are an error', () => {
  for (const format of LEGACY_FORMATS) {
    const fixture = first(format);
    const [a, b] = fixture.shares;
    assert.equal(recover([a, a, b, b]).text(), fixture.text, format);
    assert.throws(() => recover([a, a]), code('ERR_INSUFFICIENT_SHARES'), format);
    assert.throws(() => recover([a]), code('ERR_INSUFFICIENT_SHARES'), format);
  }
  const [a, b] = first('secrets.js').shares;
  const conflicting = { ...a, value: a.value.slice(0, -1) + (a.value.at(-1) === '0' ? '1' : '0') };
  assert.throws(() => recover([a, conflicting, b]), code('ERR_DUPLICATE_SHARE'));
});

test('shares of different formats, or of different secrets, do not combine', () => {
  const browser = first('secrets.js');
  const server = first('shamir');
  const sssa = first('sssa');
  const ss1 = split('x', { shares: 2, threshold: 2 });
  assert.throws(() => recover([browser.shares[0], server.shares[1]]), code('ERR_MIXED_SHARES'));
  assert.throws(() => recover([browser.shares[0], sssa.shares[1]]), code('ERR_MIXED_SHARES'));
  assert.throws(() => recover([ss1[0], browser.shares[1]]), code('ERR_MIXED_SHARES'));
  assert.throws(() => combine([ss1[0], browser.shares[1].value]), code('ERR_INVALID_SHARE'), 'combine() is ss1 only');

  for (const format of LEGACY_FORMATS) {
    const longer = fixtures.find((f) => f.format === format && f.text.length === 200);
    const shorter = fixtures.find((f) => f.format === format && f.text === 'a');
    assert.throws(() => recover([longer.shares[0], shorter.shares[1]]), code('ERR_MIXED_SHARES'), format);
  }
});

test('too few secrets.js shares are detected by the missing marker (usually)', () => {
  // secrets.js stores a 1-bit marker above the secret. With too few shares the
  // reconstruction is random, and the marker byte is right 1 time in 256.
  let detected = 0;
  let total = 0;
  for (const fixture of fixtures.filter((f) => f.format === 'secrets.js' && f.threshold >= 3)) {
    total++;
    try {
      const text = recover(fixture.shares.slice(0, fixture.threshold - 1)).text();
      assert.notEqual(text, fixture.text);
    } catch (error) {
      assert.ok(['ERR_INTEGRITY', 'ERR_INVALID_UTF8'].includes(error.code), error.message);
      detected++;
    }
  }
  assert.ok(total >= 10 && detected >= total - 1, `${detected} of ${total}`);
});

test('too few shares in the unverifiable formats never return the real secret', () => {
  for (const fixture of fixtures.filter((f) => f.format !== 'secrets.js' && f.threshold >= 3)) {
    try {
      assert.notEqual(recover(fixture.shares.slice(0, fixture.threshold - 1)).text(), fixture.text);
    } catch (error) {
      assert.ok(error instanceof SecretSlicesError, String(error));
    }
  }
});

test('malformed legacy shares are rejected with a clear error', () => {
  const browser = first('secrets.js').shares[0].value;
  assert.equal(validate(`9${browser.slice(1)}`).code, 'ERR_UNSUPPORTED_VERSION', 'secrets.js shares in another field size');
  assert.equal(validate(`800${browser.slice(3)}`).code, 'ERR_INVALID_SHARE', 'id zero');
  assert.equal(validate(`${browser}0`).code, 'ERR_INVALID_SHARE', 'odd number of hex digits');
  assert.equal(validate({ part: 0, value: '1,2,3' }).code, 'ERR_INVALID_SHARE');
  assert.equal(validate({ part: 256, value: '1,2,3' }).code, 'ERR_INVALID_SHARE');
  assert.equal(validate({ part: 'x', value: '1,2,3' }).code, 'ERR_INVALID_SHARE');
  assert.equal(validate({ part: 1, value: '1,256,3' }).code, 'ERR_INVALID_SHARE');
  assert.equal(validate({ part: 1, value: 'hello' }).valid, false);
  assert.equal(validate({ part: 1 }).valid, false);
  const sssa = first('sssa').shares[0];
  assert.equal(validate(sssa.slice(0, -1)).valid, false);
  assert.equal(validate(sssa.slice(0, 44)).valid, false, 'half a block');
  assert.equal(parseLegacyShare('ss1.AAAA'), null);
  assert.equal(parseLegacyShare(42), null);
  assert.equal(parseLegacyShare(null), null);
  assert.throws(() => recover([{ part: 1, value: 'hello' }, { part: 2, value: 'world' }]), code('ERR_INVALID_SHARE'));
  assert.throws(() => recover('{"part": 1, "value": '), code('ERR_INVALID_SHARE'));
  assert.throws(() => recover('{"part": 1, "value": "1,2"}\n{not json}'), code('ERR_INVALID_SHARE'));
  assert.throws(() => recover([]), code('ERR_INVALID_ARGUMENT'));
  assert.throws(() => recover('   '), code('ERR_INVALID_ARGUMENT'));
  assert.throws(() => recover(42), code('ERR_INVALID_SHARE'));
  assert.throws(() => recover(null), code('ERR_INVALID_SHARE'));
});

test('sssa shares in the standard base64 alphabet are accepted, as the original did', () => {
  const fixture = fixtures.find((f) => f.format === 'sssa' && f.shares.some((s) => /[-_]/.test(s)));
  const standard = fixture.shares.map((s) => s.replace(/-/g, '+').replace(/_/g, '/'));
  assert.equal(recover(standard.slice(0, fixture.threshold)).text(), fixture.text);
});

test('the secretslices/legacy entry point works on its own', () => {
  const fixture = first('shamir');
  const parsed = fixture.shares.slice(0, 2).map(parseLegacyShare);
  assert.equal(new TextDecoder().decode(combineLegacyShares(parsed)), fixture.text);
});

test('sssa text is read whether it was written as UTF-8 (Go) or CESU-8 (JavaScript)', () => {
  const emoji = fixtures.find((f) => f.encoder === 'sssa-js 0.0.1' && f.text.includes('😀'));
  assert.equal(recover(emoji.shares).text(), emoji.text);
  const { cesu8ToUtf8 } = legacyModule;
  const utf8Bytes = new TextEncoder().encode('a😀é世\u{10000}\u{10ffff}퟿');
  const cesu = Uint8Array.from(Buffer.from('61eda0bdedb880c3a9e4b896eda080edb080edafbfedbfbfed9fbfee8080', 'hex'));
  assert.deepEqual(cesu8ToUtf8(cesu), utf8Bytes);
  assert.deepEqual(cesu8ToUtf8(utf8Bytes), utf8Bytes, 'UTF-8 passes through unchanged');
  assert.deepEqual(cesu8ToUtf8(Uint8Array.of(0xed, 0xa0, 0xbd)), Uint8Array.of(0xed, 0xa0, 0xbd), 'a lone surrogate is left for the decoder to reject');
});
