// Arithmetic in GF(2^8), written without lookup tables and without branches
// on secret data, so that timing does not depend on the secret through this
// code. (A JavaScript engine gives no hard constant-time guarantee; this is
// best effort.)
//
// A field is selected by the low byte of its reduction polynomial:
//   AES  x^8+x^4+x^3+x+1    (0x11b) - the ss1 format and the `shamir` package
//   RS   x^8+x^4+x^3+x^2+1  (0x11d) - secrets.js shares

export const AES = 0x1b;
export const RS = 0x1d;

/** Product of two field elements. Constant time in both operands. */
export function mul(a, b, poly = AES) {
  let r = 0;
  for (let i = 0; i < 8; i++) {
    r ^= a & -(b & 1);
    a = ((a << 1) ^ (poly & -(a >>> 7))) & 0xff;
    b >>>= 1;
  }
  return r;
}

/** Multiplicative inverse (a^254). Only ever called on public values. */
export function inv(a, poly = AES) {
  if (a === 0) throw new RangeError('zero has no inverse in GF(2^8)');
  let result = 1;
  let base = a;
  for (let e = 254; e > 0; e >>>= 1) {
    if (e & 1) result = mul(result, base, poly);
    base = mul(base, base, poly);
  }
  return result;
}

// Four field elements packed in one 32-bit word, each multiplied by the same
// PUBLIC constant c. Branching on the bits of c is safe; the packed secret
// bytes only go through shifts, masks and XORs.
function mulWord(v, c, poly) {
  let r = 0;
  for (let bit = 7; bit >= 0; bit--) {
    r = ((r & 0x7f7f7f7f) << 1) ^ (((r >>> 7) & 0x01010101) * poly);
    if ((c >>> bit) & 1) r ^= v;
  }
  return r;
}

/**
 * acc[i] = acc[i] * c + add[i] for every packed element: one Horner step.
 * @param {Uint32Array} acc
 * @param {number} c public field element
 * @param {Uint32Array} add
 */
export function hornerStep(acc, c, add, poly = AES) {
  for (let i = 0; i < acc.length; i++) acc[i] = mulWord(acc[i], c, poly) ^ add[i];
}

/**
 * acc[i] += src[i] * c for every packed element.
 * @param {Uint32Array} acc
 * @param {Uint32Array} src
 * @param {number} c public field element
 */
export function addScaled(acc, src, c, poly = AES) {
  for (let i = 0; i < acc.length; i++) acc[i] ^= mulWord(src[i], c, poly);
}

/**
 * Lagrange basis values at zero: weights[i] = prod_{j != i} x_j / (x_j - x_i).
 * The interpolated constant term is then sum_i y_i * weights[i].
 * @param {ArrayLike<number>} xs distinct, non-zero, public
 * @returns {Uint8Array}
 */
export function lagrangeAtZero(xs, poly = AES) {
  const weights = new Uint8Array(xs.length);
  for (let i = 0; i < xs.length; i++) {
    let numerator = 1;
    let denominator = 1;
    for (let j = 0; j < xs.length; j++) {
      if (j === i) continue;
      numerator = mul(numerator, xs[j], poly);
      denominator = mul(denominator, xs[j] ^ xs[i], poly);
    }
    weights[i] = mul(numerator, inv(denominator, poly), poly);
  }
  return weights;
}

/** A zeroed Uint32Array able to hold `byteLength` bytes, and its byte view. */
export function packed(byteLength) {
  const words = new Uint32Array(Math.ceil(byteLength / 4));
  return { words, bytes: new Uint8Array(words.buffer) };
}

/**
 * Interpolates byte vectors at zero.
 * @param {number[]} xs distinct non-zero x coordinates
 * @param {Uint8Array[]} ys equal-length y vectors
 * @returns {Uint8Array} the constant terms
 */
export function interpolateAtZero(xs, ys, poly = AES) {
  const length = ys[0].length;
  const weights = lagrangeAtZero(xs, poly);
  const acc = packed(length);
  const term = packed(length);
  for (let i = 0; i < ys.length; i++) {
    term.bytes.set(ys[i]);
    addScaled(acc.words, term.words, weights[i], poly);
  }
  term.words.fill(0);
  return acc.bytes.slice(0, length);
}
