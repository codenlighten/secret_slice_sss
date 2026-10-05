import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SecretSlicesError, combine, combineText, inspect, recover, split, validate } from '../src/index.js';
import { splitWith } from '../src/core.js';
import { decodeShare, encodeShare } from '../src/format.js';
import { fromHex, seededFill, subsets, toHex, utf8 } from './helpers.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/ss1.json', import.meta.url), 'utf8'));
const code = (expected) => (error) => {
  assert.ok(error instanceof SecretSlicesError, `expected a SecretSlicesError, got ${error}`);
  assert.equal(error.code, expected, error.message);
  return true;
};

// ------------------------------------------------- independent reference decoder
// Written from docs/FORMAT.md only, sharing no code with src/: log/antilog
// tables, node:crypto, Buffer. If src/ and this ever disagree, one is wrong.

const EXP = new Uint8Array(510);
const LOG = new Uint8Array(256);
for (let i = 0, x = 1; i < 255; i++) {
  EXP[i] = EXP[i + 255] = x;
  LOG[x] = i;
  x ^= (x << 1) ^ (x & 0x80 ? 0x11b : 0); // multiply by the generator 3
  x &= 0xff;
}
const refMul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
const refDiv = (a, b) => (a ? EXP[LOG[a] + 255 - LOG[b]] : 0);
const sha = (...parts) => createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();

function referenceDecode(texts) {
  const parsed = texts.map((text) => {
    assert.ok(text.startsWith('ss1.'));
    const bytes = Buffer.from(text.slice(4), 'base64url');
    const unchecked = bytes.subarray(0, -4);
    assert.deepEqual(sha('secretslices/v1/share\0', unchecked).subarray(0, 4), bytes.subarray(-4));
    return { threshold: bytes[0], x: bytes[1], setId: bytes.subarray(2, 10), body: unchecked.subarray(10) };
  });
  const payload = Buffer.alloc(parsed[0].body.length);
  for (let i = 0; i < payload.length; i++) {
    let value = 0;
    for (const a of parsed) {
      let weight = 1;
      for (const b of parsed) if (b !== a) weight = refMul(weight, refDiv(b.x, b.x ^ a.x));
      value ^= refMul(a.body[i], weight);
    }
    payload[i] = value;
  }
  let end = payload.length - 1;
  while (payload[end] === 0) end--;
  assert.equal(payload[end], 0x80);
  const secret = payload.subarray(16, end);
  const digest = sha('secretslices/v1/secret\0', [parsed[0].threshold], parsed[0].setId, secret).subarray(0, 16);
  assert.deepEqual(payload.subarray(0, 16), digest);
  return secret;
}

// ------------------------------------------------------------------- vectors

test('frozen vectors: the format has not changed', () => {
  assert.ok(vectors.length >= 20);
  vectors.forEach((vector, i) => {
    const secret = fromHex(vector.secret);
    const seed = `ss1-vector-${[0, 1, 2, 3, 4, 5].find((s) => seedMatches(s, vector))}-${vector.shares}-${vector.threshold}-${vector.padTo}`;
    const again = splitWith(seededFill(seed), secret, vector);
    for (const share of vector.encoded) assert.ok(again.includes(share), `vector ${i}: encoder output changed`);
    assert.equal(toHex(combine(vector.encoded.slice(-vector.threshold))), vector.secret, `vector ${i}`);
  });

  function seedMatches(s, vector) {
    const out = splitWith(seededFill(`ss1-vector-${s}-${vector.shares}-${vector.threshold}-${vector.padTo}`), fromHex(vector.secret), vector);
    return out.includes(vector.encoded[0]);
  }
});

test('frozen vectors decode with the independent reference decoder', () => {
  for (const vector of vectors) {
    assert.equal(toHex(referenceDecode(vector.encoded.slice(0, vector.threshold))), vector.secret);
  }
});

test('fresh shares decode with the independent reference decoder', () => {
  for (let round = 0; round < 50; round++) {
    const secret = randomBytes(round * 3);
    const shares = split(secret, { shares: 6, threshold: 2 + (round % 5), padTo: 1 + (round % 7) });
    assert.equal(toHex(referenceDecode(shares.slice(0, 2 + (round % 5)))), toHex(secret));
  }
});

// ----------------------------------------------------------------- round trips

test('every threshold-sized subset recovers the secret, in any order', () => {
  const secret = utf8('correct horse battery staple');
  for (const [n, k] of [[2, 2], [3, 2], [5, 3], [6, 4], [7, 7]]) {
    const shares = split(secret, { shares: n, threshold: k });
    assert.equal(shares.length, n);
    for (const subset of subsets(shares, k)) {
      assert.deepEqual(combine(subset), secret);
      assert.deepEqual(combine([...subset].reverse()), secret);
    }
    assert.deepEqual(combine(shares), secret, 'all shares');
  }
});

test('secrets of every length from 0 to 70 bytes survive, including zero bytes at either end', () => {
  for (let length = 0; length <= 70; length++) {
    const secret = Uint8Array.from(randomBytes(length));
    if (length > 0) secret[length - 1] = 0;
    if (length > 1) secret[0] = 0;
    assert.deepEqual(combine(split(secret, { shares: 3, threshold: 2 }).slice(1)), secret, `length ${length}`);
  }
  for (const awkward of [[], [0], [0, 0, 0], [0x80], [0x80, 0], [0, 0x80, 0, 0], [0xff]]) {
    const secret = Uint8Array.from(awkward);
    assert.deepEqual(combine(split(secret, { shares: 2, threshold: 2, padTo: 4 })), secret);
  }
});

test('text secrets round-trip exactly', () => {
  for (const text of ['', 'a', 'abc\0\0', '\0', 'こんにちは、世界', 'hi 😀 there', 'line\nbreak\r\n', ' padded ']) {
    const shares = split(text, { shares: 3, threshold: 2 });
    assert.equal(combineText(shares.slice(0, 2)), text);
    assert.equal(recover(shares).text(), text);
  }
});

test('the extremes: 255 shares, threshold 255, and a megabyte', () => {
  const secret = randomBytes(64);
  const many = split(secret, { shares: 255, threshold: 255 });
  assert.deepEqual(Buffer.from(combine(many)), secret);
  assert.throws(() => combine(many.slice(1)), code('ERR_INSUFFICIENT_SHARES'));
  assert.deepEqual(Buffer.from(combine(split(secret, { shares: 255, threshold: 2 }).slice(253))), secret);

  const big = randomBytes(1 << 20);
  assert.deepEqual(Buffer.from(combine(split(big, { shares: 3, threshold: 2 }).slice(1))), big);
});

test('split does not modify the caller\'s bytes and never repeats itself', () => {
  const secret = utf8('do not touch');
  const copy = Uint8Array.from(secret);
  const a = split(secret, { shares: 3, threshold: 2 });
  const b = split(secret, { shares: 3, threshold: 2 });
  assert.deepEqual(secret, copy);
  assert.equal(new Set([...a, ...b]).size, 6);
  assert.notEqual(inspect(a[0]).setId, inspect(b[0]).setId);
});

// ---------------------------------------------------------------- share format

test('share size is the secret plus a fixed 31 bytes, and padTo hides the length', () => {
  for (const length of [0, 1, 32, 1000]) {
    const share = split(new Uint8Array(length), { shares: 2, threshold: 2 })[0];
    assert.equal(Buffer.from(share.slice(4), 'base64url').length, length + 31);
  }
  const lengths = new Set();
  for (let length = 0; length < 32; length++) {
    lengths.add(split(new Uint8Array(length), { shares: 2, threshold: 2, padTo: 32 })[0].length);
  }
  assert.equal(lengths.size, 1, 'secrets of 0 to 31 bytes are indistinguishable by share length');
  assert.equal(inspect(split('abc', { shares: 2, threshold: 2 })[0]).maxSecretBytes, 3);
  assert.equal(inspect(split('abc', { shares: 2, threshold: 2, padTo: 32 })[0]).maxSecretBytes, 31);
});

test('inspect and validate describe a share', () => {
  const shares = split('s', { shares: 4, threshold: 3 });
  const info = inspect(shares[2]);
  assert.deepEqual({ format: info.format, threshold: info.threshold, index: info.index }, { format: 'ss1', threshold: 3, index: 3 });
  assert.match(info.setId, /^[0-9a-f]{16}$/);
  assert.deepEqual(validate(shares[2]), { valid: true, format: 'ss1', threshold: 3, index: 3, setId: info.setId });
  assert.deepEqual(validate(`  ${shares[2]}\n`).valid, true, 'surrounding whitespace is ignored');
});

test('share bodies are statistically uniform', () => {
  // 200 kB of share body for an all-zero secret, from a fixed seed (so this
  // test cannot flake): chi-squared against the uniform distribution.
  const shares = splitWith(seededFill('uniformity'), new Uint8Array(100_000), { shares: 2, threshold: 2 });
  const counts = new Array(256).fill(0);
  let total = 0;
  for (const share of shares) {
    for (const byte of decodeShare(share).body) { counts[byte]++; total++; }
  }
  const expected = total / 256;
  const chi2 = counts.reduce((sum, c) => sum + (c - expected) ** 2 / expected, 0);
  assert.ok(chi2 > 180 && chi2 < 340, `chi-squared ${chi2.toFixed(1)} is outside the range expected for 255 degrees of freedom`);
});

// ------------------------------------------------------------------- failures

test('split rejects bad arguments instead of producing weak shares', () => {
  const bad = (secret, options) => assert.throws(() => split(secret, options), code('ERR_INVALID_ARGUMENT'));
  bad('s', { shares: 3, threshold: 1 });   // every share would be the secret
  bad('s', { shares: 3, threshold: 0 });
  bad('s', { shares: 1, threshold: 1 });
  bad('s', { shares: 3, threshold: 4 });
  bad('s', { shares: 256, threshold: 2 });
  bad('s', { shares: 3.5, threshold: 2 });
  bad('s', { shares: '3', threshold: '2' });
  bad('s', { shares: 3, threshold: NaN });
  bad('s', { shares: 3 });
  bad('s', {});
  bad('s');
  bad('s', null);
  bad('s', { shares: 3, threshold: 2, padTo: 0 });
  bad('s', { shares: 3, threshold: 2, padTo: 1.5 });
  bad('s', { shares: 3, threshold: 2, padTo: 65537 });
  bad(12345, { shares: 3, threshold: 2 });
  bad(null, { shares: 3, threshold: 2 });
  bad(undefined, { shares: 3, threshold: 2 });
  bad([1, 2, 3], { shares: 3, threshold: 2 });
  bad(new ArrayBuffer(4), { shares: 3, threshold: 2 });
  bad('a\ud800b', { shares: 3, threshold: 2 });   // unpaired surrogate
});

test('too few shares is reported as such, with the numbers', () => {
  const shares = split('s', { shares: 5, threshold: 4 });
  assert.throws(() => combine(shares.slice(0, 3)), (error) => {
    code('ERR_INSUFFICIENT_SHARES')(error);
    assert.equal(error.required, 4);
    assert.equal(error.provided, 3);
    return true;
  });
  assert.throws(() => combine([shares[0], shares[0], shares[0], shares[0]]), code('ERR_INSUFFICIENT_SHARES'), 'repeats do not count');
  assert.equal(combineText([shares[0], shares[0], shares[1], shares[2], shares[3]]), 's', 'an exact repeat is harmless');
});

test('changing any single character of a share is detected', () => {
  const shares = split('a secret worth protecting', { shares: 3, threshold: 2 });
  const [target] = shares;
  for (let position = 0; position < target.length; position++) {
    for (const replacement of ['A', 'b', '_', '9']) {
      if (target[position] === replacement) continue;
      const altered = target.slice(0, position) + replacement + target.slice(position + 1);
      assert.throws(() => combine([altered, shares[1]]), SecretSlicesError, `position ${position}`);
      assert.equal(validate(altered).valid, false);
    }
  }
  for (let cut = 1; cut < target.length; cut++) {
    assert.throws(() => combine([target.slice(0, cut), shares[1]]), SecretSlicesError, `cut to ${cut}`);
    assert.throws(() => combine([target.slice(cut), shares[1]]), SecretSlicesError);
  }
  assert.throws(() => combine([`${target}A`, shares[1]]), SecretSlicesError);
});

test('a damaged share is reported by its position', () => {
  const shares = split('s', { shares: 3, threshold: 2 });
  const damaged = `${shares[1].slice(0, -1)}${shares[1].at(-1) === 'A' ? 'Q' : 'A'}`;
  assert.throws(() => combine([shares[0], damaged]), (error) => {
    assert.ok(['ERR_SHARE_CHECKSUM', 'ERR_INVALID_SHARE'].includes(error.code));
    assert.equal(error.shareIndex, 1);
    assert.match(error.message, /^share 2: /);
    return true;
  });
});

test('shares from different splits do not combine', () => {
  const a = split('same', { shares: 3, threshold: 2 });
  const b = split('same', { shares: 3, threshold: 2 });
  assert.throws(() => combine([a[0], b[1]]), code('ERR_MIXED_SHARES'));
  const c = split('longer secret', { shares: 3, threshold: 2 });
  assert.throws(() => combine([a[0], c[1]]), code('ERR_MIXED_SHARES'));
});

// A share whose contents are deliberately wrong but whose checksum is right:
// what a person editing a share, rather than a typo, would produce.
function reencode(share, change) {
  const decoded = decodeShare(share);
  change(decoded);
  return encodeShare(decoded);
}

test('a deliberately altered share with a correct checksum fails the digest check', () => {
  const shares = split('the original secret', { shares: 3, threshold: 2 });
  for (let position = 0; position < decodeShare(shares[0]).body.length; position++) {
    const forged = reencode(shares[0], (s) => { s.body[position] ^= 0x01; });
    assert.equal(validate(forged).valid, true, 'the forged share looks fine on its own');
    assert.throws(() => combine([forged, shares[1]]), code('ERR_INTEGRITY'), `body byte ${position}`);
    assert.throws(() => combine([forged, shares[1], shares[2]]), code('ERR_INTEGRITY'));
  }
});

test('headers edited to lower the threshold do not yield a secret', () => {
  const shares = split('needs three', { shares: 5, threshold: 3 });
  const lowered = shares.slice(0, 2).map((share) => reencode(share, (s) => { s.threshold = 2; }));
  assert.throws(() => combine(lowered), code('ERR_INTEGRITY'));
  const mixed = [reencode(shares[0], (s) => { s.threshold = 2; }), shares[1], shares[2]];
  assert.throws(() => combine(mixed), code('ERR_MIXED_SHARES'));
  const all = shares.slice(0, 3).map((share) => reencode(share, (s) => { s.threshold = 2; }));
  assert.throws(() => combine(all), code('ERR_INTEGRITY'), 'the digest binds the threshold');
});

test('re-indexed, re-labelled and conflicting shares are rejected', () => {
  const shares = split('s', { shares: 3, threshold: 2 });
  assert.throws(() => combine([reencode(shares[0], (s) => { s.index = 9; }), shares[1]]), code('ERR_INTEGRITY'));
  assert.throws(() => combine([reencode(shares[0], (s) => { s.setId[0] ^= 1; }), shares[1]]), code('ERR_MIXED_SHARES'));
  const relabelled = shares.map((share) => reencode(share, (s) => { s.setId[0] ^= 1; }));
  assert.throws(() => combine(relabelled), code('ERR_INTEGRITY'), 'the digest binds the set id');
  const conflicting = reencode(shares[0], (s) => { s.body[0] ^= 1; });
  assert.throws(() => combine([shares[0], conflicting, shares[1]]), code('ERR_DUPLICATE_SHARE'));
  assert.throws(() => decodeShare(reencode(shares[0], (s) => { s.index = 0; })), code('ERR_INVALID_SHARE'));
  assert.throws(() => decodeShare(reencode(shares[0], (s) => { s.threshold = 1; })), code('ERR_INVALID_SHARE'));
});

test('combine rejects things that are not a list of shares', () => {
  const [share] = split('s', { shares: 2, threshold: 2 });
  for (const input of [undefined, null, 5, {}, share]) assert.throws(() => combine(input), code('ERR_INVALID_ARGUMENT'));
  assert.throws(() => combine([]), code('ERR_INVALID_ARGUMENT'));
  assert.throws(() => combine([share, 5]), code('ERR_INVALID_SHARE'));
  assert.throws(() => combine([share, null]), code('ERR_INVALID_SHARE'));
  assert.throws(() => combine(['not a share', share]), code('ERR_INVALID_SHARE'));
  assert.throws(() => combine(['ss1.', share]), code('ERR_INVALID_SHARE'));
  assert.throws(() => combine([`ss2.${share.slice(4)}`, share]), code('ERR_UNSUPPORTED_VERSION'));
  assert.equal(validate(`ss2.${share.slice(4)}`).code, 'ERR_UNSUPPORTED_VERSION');
  assert.equal(combineText(new Set(split('iterable', { shares: 2, threshold: 2 }))), 'iterable');
});

test('combineText refuses to return mangled text for a binary secret', () => {
  const shares = split(Uint8Array.of(0xff, 0xfe, 0x00), { shares: 2, threshold: 2 });
  assert.throws(() => combineText(shares), code('ERR_INVALID_UTF8'));
  assert.deepEqual(combine(shares), Uint8Array.of(0xff, 0xfe, 0x00));
});

test('a share written in groups, or wrapped over lines, is the same share', () => {
  const shares = split('typed back in from paper', { shares: 3, threshold: 2 });
  const grouped = shares.map((share) => share.match(/.{1,4}/g).join(' '));
  const wrapped = shares.map((share) => share.match(/.{1,17}/g).join('\n  '));
  assert.equal(combineText([grouped[0], wrapped[2]]), 'typed back in from paper');
  assert.equal(inspect(grouped[1]).index, 2);
  assert.equal(validate(`\t${grouped[1]}\n`).valid, true);

  // Several shares in one pasted text: a new share begins at each "ss1."
  assert.equal(recover(grouped.slice(0, 2).join('\n')).text(), 'typed back in from paper');
  assert.equal(recover(wrapped.slice(1).join('\n\n')).text(), 'typed back in from paper');
  assert.equal(recover(`${grouped[0]} ${grouped[2]}`).text(), 'typed back in from paper', 'two on one line');
  assert.equal(recover(`"${grouped[0]}",\n"${grouped[1]}"`).text(), 'typed back in from paper');
  assert.equal(recover(shares.map((s) => s.replace('ss1.', 'ss1. ')).join('\n')).text(), 'typed back in from paper');

  // The prefix itself must be intact, and every entry point agrees on that.
  const brokenPrefix = shares[0].replace('ss1.', 's s1.');
  assert.equal(validate(brokenPrefix).valid, false);
  assert.throws(() => combineText([brokenPrefix, shares[1]]), SecretSlicesError);
  assert.throws(() => recover([brokenPrefix, shares[1]]), SecretSlicesError);

  // A wrong join is caught by the checksum, never silently accepted.
  const missingGroup = grouped[0].split(' ').filter((_, i) => i !== 5).join(' ');
  assert.throws(() => recover([missingGroup, shares[1]].join('\n')), SecretSlicesError);
  assert.throws(() => recover(`${grouped[0]} stray ${shares[1]}`), SecretSlicesError);
  assert.throws(() => recover(`${shares[0]}\nstray!\n${shares[1]}`), code('ERR_MIXED_SHARES'));
});
