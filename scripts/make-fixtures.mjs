// Regenerates test/fixtures/*.json. NOT part of the test run: the fixtures are
// committed, and the tests read them.
//
// Legacy fixtures are produced by the ORIGINAL encoders, never by this
// library, so the decoders are tested against what really shipped:
//
//   REFS/oldsecrets.js                 secrets.js 0.1.8, cut verbatim from the
//                                      2024 secretslices.com page (smartshamir
//                                      repo, public/index.html)
//   REFS/node_modules/secrets.js-grempe  2.0.0
//   REFS/node_modules/shamir             0.7.1 (secretslices.com server API)
//   REFS/node_modules/crypto-js          4.x (password option of the 2024 app)
//   REFS/sssa.js                         SSSaaS/sssa-js at commit 9a2a533, with
//                                        its four dependencies installed
//
//   REFS=/path/to/refs node scripts/make-fixtures.mjs

import { randomBytes } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { splitWith } from '../src/core.js';
import { seededFill, toHex } from '../test/helpers.js';

const refs = process.env.REFS;
if (!refs) throw new Error('set REFS to the directory holding the reference libraries');
const require = createRequire(`${refs}/`);

const texts = [
  'a',
  'test-pass',
  'witch collapse practice feed shame open despair creek road again ice least',
  'L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ',
  'こんにちは、世界 — ünïcödé ✓ 😀',
  'x'.repeat(200),
];
const shapes = [[2, 2], [3, 2], [5, 3], [7, 7]];

const legacy = [];
const oldSecrets = require('./oldsecrets.js');
const grempe = require('secrets.js-grempe');
const shamir = require('shamir');
const CryptoJS = require('crypto-js');
globalThis.testing = true;
const sssa = require('./sssa.js');

for (const text of texts) {
  for (const [shares, threshold] of shapes) {
    const hex = Buffer.from(text, 'utf8').toString('hex');
    legacy.push({
      encoder: 'secrets.js 0.1.8 (secretslices.com 2024 browser app)', format: 'secrets.js', text, threshold,
      shares: oldSecrets.share(hex, shares, threshold).map((value, i) => ({ part: i + 1, value })),
    });
    legacy.push({
      encoder: 'secrets.js-grempe 2.0.0', format: 'secrets.js', text, threshold,
      shares: grempe.share(hex, shares, threshold),
    });
    const parts = shamir.split(randomBytes, shares, threshold, new TextEncoder().encode(text));
    legacy.push({
      encoder: 'shamir 0.7.1 (secretslices.com 2024 server API)', format: 'shamir', text, threshold,
      shares: Object.entries(parts).map(([part, value]) => ({ part, value: Array.from(value).toString() })),
    });
    legacy.push({
      encoder: 'sssa-js 0.0.1', format: 'sssa', text, threshold,
      shares: sssa.create(threshold, shares, text),
    });
  }
}
legacy.push({
  // The upstream test does not state its threshold; 4 shares are enough and 3 are not.
  encoder: 'sssa-js upstream test vector (go-libtest)', format: 'sssa', text: 'test-pass', threshold: 4,
  shares: [
    'U1k9koNN67-og3ZY3Mmikeyj4gEFwK4HXDSglM8i_xc=yA3eU4_XYcJP0ijD63Tvqu1gklhBV32tu8cHPZXP-bk=',
    'O7c_iMBaGmQQE_uU0XRCPQwhfLBdlc6jseTzK_qN-1s=ICDGdloemG50X5GxteWWVZD3EGuxXST4UfZcek_teng=',
    '8qzYpjk7lmB7cRkOl6-7srVTKNYHuqUO2WO31Y0j1Tw=-g6srNoWkZTBqrKA2cMCA-6jxZiZv25rvbrCUWVHb5g=',
    'wGXxa_7FPFSVqdo26VKdgFxqVVWXNfwSDQyFmCh2e5w=8bTrIEs0e5FeiaXcIBaGwtGFxeyNtCG4R883tS3MsZ0=',
    'j8-Y4_7CJvL8aHxc8WMMhP_K2TEsOkxIHb7hBcwIBOo=T5-EOvAlzGMogdPawv3oK88rrygYFza3KSki2q8WEgs=',
  ],
});

const passwords = [];
for (const [text, password] of [['hello', 'pw'], [texts[2], 'correct horse — bättery ✓'], ['', 'empty'], ['y'.repeat(100), '']]) {
  const ciphertext = CryptoJS.AES.encrypt(text, password).toString();
  passwords.push({
    text, password, ciphertext,
    shares: oldSecrets.share(Buffer.from(ciphertext, 'utf8').toString('hex'), 3, 2).map((value, i) => ({ part: i + 1, value })),
  });
}

const ss1 = [];
const secrets = [new Uint8Array(0), Uint8Array.of(0), Uint8Array.of(0x80, 0, 0), new TextEncoder().encode(texts[2]),
  new TextEncoder().encode(texts[4]), Uint8Array.from({ length: 256 }, (_, i) => i)];
secrets.forEach((secret, i) => {
  for (const [shares, threshold, padTo] of [[2, 2, 1], [5, 3, 1], [5, 3, 32], [255, 2, 1], [255, 255, 16]]) {
    if (threshold === 255 && i !== 3) continue;
    const out = splitWith(seededFill(`ss1-vector-${i}-${shares}-${threshold}-${padTo}`), secret, { shares, threshold, padTo });
    // For the two 255-share cases keep only what a decoder needs, to keep the file small.
    const kept = shares === 255 ? [...out.slice(0, threshold === 255 ? 255 : 2), out[254]] : out;
    ss1.push({ secret: toHex(secret), shares, threshold, padTo, encoded: [...new Set(kept)] });
  }
});

writeFileSync(new URL('../test/fixtures/legacy.json', import.meta.url), `${JSON.stringify(legacy, null, 1)}\n`);
writeFileSync(new URL('../test/fixtures/legacy-password.json', import.meta.url), `${JSON.stringify(passwords, null, 1)}\n`);
writeFileSync(new URL('../test/fixtures/ss1.json', import.meta.url), `${JSON.stringify(ss1, null, 1)}\n`);
console.log(`legacy: ${legacy.length}, password: ${passwords.length}, ss1: ${ss1.length}`);
