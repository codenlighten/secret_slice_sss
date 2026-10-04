import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { AES, RS, addScaled, hornerStep, interpolateAtZero, inv, lagrangeAtZero, mul, packed } from '../src/gf256.js';

// An independent reference: schoolbook carry-less multiply, then reduction.
function referenceMul(a, b, modulus) {
  let product = 0;
  for (let i = 0; i < 8; i++) if ((b >> i) & 1) product ^= a << i;
  for (let bit = 15; bit >= 8; bit--) if ((product >> bit) & 1) product ^= modulus << (bit - 8);
  return product;
}

for (const [name, poly, modulus] of [['AES 0x11b', AES, 0x11b], ['RS 0x11d', RS, 0x11d]]) {
  test(`${name}: mul agrees with the reference for all 65536 pairs`, () => {
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        if (mul(a, b, poly) !== referenceMul(a, b, modulus)) assert.fail(`${a} * ${b}`);
      }
    }
  });

  test(`${name}: every non-zero element has an inverse`, () => {
    for (let a = 1; a < 256; a++) assert.equal(mul(a, inv(a, poly), poly), 1);
    assert.throws(() => inv(0, poly), RangeError);
  });

  test(`${name}: packed operations agree with scalar mul for every constant`, () => {
    for (let c = 0; c < 256; c++) {
      const source = packed(256);
      const add = packed(256);
      for (let i = 0; i < 256; i++) source.bytes[i] = i;
      add.bytes.set(randomBytes(256));

      const scaled = packed(256);
      scaled.bytes.set(add.bytes);
      addScaled(scaled.words, source.words, c, poly);
      const horner = packed(256);
      horner.bytes.set(source.bytes);
      hornerStep(horner.words, c, add.words, poly);

      for (let i = 0; i < 256; i++) {
        const expected = mul(i, c, poly) ^ add.bytes[i];
        if (scaled.bytes[i] !== expected || horner.bytes[i] !== expected) assert.fail(`element ${i}, constant ${c}`);
      }
    }
  });

  test(`${name}: interpolation recovers the constant term of random polynomials`, () => {
    for (let degree = 1; degree <= 12; degree++) {
      const coefficients = [...randomBytes(degree + 1)];
      const evaluate = (x) => coefficients.reduceRight((acc, c) => mul(acc, x, poly) ^ c, 0);
      const xs = [...new Set(randomBytes(64))].filter((x) => x !== 0).slice(0, degree + 1);
      const ys = xs.map((x) => Uint8Array.of(evaluate(x)));
      assert.equal(interpolateAtZero(xs, ys, poly)[0], coefficients[0]);
      const weights = lagrangeAtZero(xs, poly);
      assert.equal(xs.reduce((acc, x, i) => acc ^ mul(evaluate(x), weights[i], poly), 0), coefficients[0]);
    }
  });
}

test('a single share value is a bijection of the random coefficient (perfect secrecy, degree 1)', () => {
  // For any secret byte s and any share index x, s + c*x takes every value
  // exactly once as c ranges over the field: one share says nothing about s.
  for (const secret of [0, 1, 0x80, 0xff]) {
    for (let x = 1; x < 256; x++) {
      const seen = new Set();
      for (let c = 0; c < 256; c++) seen.add(secret ^ mul(c, x));
      assert.equal(seen.size, 256);
    }
  }
});

test('packed() handles lengths that are not multiples of four', () => {
  for (const length of [0, 1, 2, 3, 4, 5, 17]) {
    const buffer = packed(length);
    assert.ok(buffer.bytes.length >= length && buffer.bytes.length % 4 === 0);
    assert.equal(buffer.words.length * 4, buffer.bytes.length);
  }
});
