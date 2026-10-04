import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { buildPage, bundle } from '../scripts/build-web.mjs';
import { combineText, split } from '../src/index.js';

const page = readFileSync(new URL('../web/index.html', import.meta.url), 'utf8');
const vectors = JSON.parse(readFileSync(new URL('./fixtures/ss1.json', import.meta.url), 'utf8'));
const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy.json', import.meta.url), 'utf8'));

test('web/index.html is up to date with the source (run "npm run build" if this fails)', () => {
  assert.equal(page, buildPage());
});

test('the page is one self-contained file', () => {
  assert.doesNotMatch(page, /<script[^>]+src=|<link[^>]+rel="stylesheet"|@import|\burl\(/i, 'no external scripts, styles or images');
  assert.equal((page.match(/<script/g) ?? []).length, 1);
  assert.equal((page.match(/<style/g) ?? []).length, 1);
  assert.doesNotMatch(page, /\sstyle="|\son[a-z]+="/, 'no inline style attributes or event handlers: the policy would block them');
  assert.doesNotMatch(page, /%[A-Z]+%/, 'no unfilled placeholders');
});

test('the security policy forbids all network access and pins the exact script and style', () => {
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(page)[1];
  const script = /<script>([\s\S]*)<\/script>/.exec(page)[1];
  const style = /<style>([\s\S]*?)<\/style>/.exec(page)[1];
  const hash = (text) => `'sha256-${createHash('sha256').update(text).digest('base64')}'`;
  assert.equal(csp, `default-src 'none'; script-src ${hash(script)}; style-src ${hash(style)}; img-src data:; base-uri 'none'; form-action 'none'`);
  assert.doesNotMatch(csp, /unsafe|https?:|\*/);
  assert.ok(page.indexOf('Content-Security-Policy') < page.indexOf('<script>'), 'the policy comes before the script');
});

test('the bundled library behaves exactly like the source', () => {
  // Run the bundle in an empty realm that has only what a browser provides.
  const context = vm.createContext({ crypto: webcrypto, TextEncoder, TextDecoder, atob, Uint8Array, Uint32Array });
  const api = vm.runInContext(bundle('src/index.js'), context);
  assert.deepEqual(Object.keys(api).sort(), ['FORMATS', 'SecretSlicesError', 'combine', 'combineText', 'inspect', 'recover', 'split', 'validate']);

  for (const vector of vectors) {
    assert.equal(Buffer.from(api.combine(vector.encoded.slice(0, vector.threshold))).toString('hex'), vector.secret);
  }
  for (const fixture of legacy) {
    assert.equal(api.recover(fixture.shares).text(), fixture.text, fixture.encoder);
  }
  assert.equal(combineText(api.split('bundle to source', { shares: 3, threshold: 2 }).slice(1)), 'bundle to source');
  assert.equal(api.combineText(split('source to bundle', { shares: 3, threshold: 2 }).slice(1)), 'source to bundle');
  assert.throws(() => api.split('s', { shares: 3, threshold: 1 }), (error) => error.code === 'ERR_INVALID_ARGUMENT' && error instanceof api.SecretSlicesError);
});

test('the bundler refuses module syntax it does not understand', () => {
  assert.throws(() => bundle('test/web.test.js'), /unsupported module syntax/);
});
