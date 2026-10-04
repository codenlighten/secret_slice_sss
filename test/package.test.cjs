// The package is ES modules only. This file is CommonJS on purpose: it checks
// that require() of the package works (Node >= 20.19), which the CommonJS
// applications that consume it depend on.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync, existsSync } = require('node:fs');
const { join } = require('node:path');

const root = join(__dirname, '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

test('require("secretslices") works from CommonJS, by package name', () => {
  // A package may import itself by name: this goes through the exports map.
  const api = require('secretslices');
  const shares = api.split('from commonjs', { shares: 3, threshold: 2 });
  assert.equal(api.combineText(shares.slice(1)), 'from commonjs');
  assert.equal(api.validate(shares[0]).valid, true);
  assert.equal(typeof require('secretslices/legacy').parseLegacyShare, 'function');
  assert.equal(typeof require('secretslices/legacy-password').decryptWithPassword, 'function');
  assert.equal(typeof require('secretslices/mnemonic').generateMnemonic, 'function');
  assert.equal(require('secretslices/package.json').version, pkg.version);
});

test('the public API is exactly what is documented', () => {
  assert.deepEqual(Object.keys(require('secretslices')).sort(),
    ['FORMATS', 'SecretSlicesError', 'combine', 'combineText', 'inspect', 'recover', 'split', 'validate']);
});

test('the package has no dependencies and no install scripts', () => {
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  for (const hook of ['preinstall', 'install', 'postinstall', 'prepare']) assert.equal(pkg.scripts[hook], undefined);
  assert.equal(existsSync(join(root, 'node_modules')), false, 'nothing is installed to run the tests');
});

test('every exported path and declared file exists, with types', () => {
  for (const [name, target] of Object.entries(pkg.exports)) {
    if (typeof target === 'string') continue;
    assert.ok(existsSync(join(root, target.default)), `${name}: ${target.default}`);
    assert.ok(existsSync(join(root, target.types)), `${name}: ${target.types}`);
  }
  assert.ok(existsSync(join(root, pkg.bin.secretslices)));
  for (const entry of pkg.files) assert.ok(existsSync(join(root, entry)), entry);
});

test('the source uses nothing that is missing in a browser', () => {
  const { readdirSync } = require('node:fs');
  for (const file of readdirSync(join(root, 'src'))) {
    if (file === 'cli.js') continue;
    const source = readFileSync(join(root, 'src', file), 'utf8');
    assert.doesNotMatch(source, /from 'node:|require\(|\bBuffer\b|\bprocess\./, file);
  }
});
