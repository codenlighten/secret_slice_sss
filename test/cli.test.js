import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateMnemonic } from '../src/mnemonic.js';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const run = (args, input = '') => spawnSync(process.execPath, [CLI, ...args], { input: Buffer.from(input) });
const legacy = JSON.parse(readFileSync(new URL('./fixtures/legacy.json', import.meta.url), 'utf8'));

test('split and combine through pipes', () => {
  const made = run(['split', '-n', '5', '-k', '3'], 'my secret phrase\n');
  assert.equal(made.status, 0, made.stderr.toString());
  const shares = made.stdout.toString().trim().split('\n');
  assert.equal(shares.length, 5);
  assert.ok(shares.every((share) => share.startsWith('ss1.')));

  const back = run(['combine'], `${shares[4]}\n${shares[0]}\n${shares[2]}\n`);
  assert.equal(back.status, 0, back.stderr.toString());
  assert.equal(back.stdout.toString(), 'my secret phrase', 'the newline added by echo is not part of the secret');
  assert.equal(back.stderr.toString(), '');

  const short = run(['combine'], `${shares[0]}\n${shares[1]}\n`);
  assert.equal(short.status, 1);
  assert.equal(short.stdout.length, 0, 'nothing is written on failure');
  assert.match(short.stderr.toString(), /needs 3 different shares, but only 2 were given/);
});

test('binary secrets and files are preserved byte for byte', () => {
  const dir = mkdtempSync(join(tmpdir(), 'secretslices-test-'));
  try {
    const secret = Buffer.from([0, 255, 10, 13, 10, 128, 0, 10]);
    const file = join(dir, 'secret.bin');
    writeFileSync(file, secret);
    const fromFile = run(['split', '--shares', '3', '--threshold', '2', '--pad-to', '64', file]);
    assert.equal(fromFile.status, 0, fromFile.stderr.toString());
    const shareFiles = fromFile.stdout.toString().trim().split('\n').map((share, i) => {
      const path = join(dir, `share-${i}.txt`);
      writeFileSync(path, `${share}\n`);
      return path;
    });
    assert.deepEqual(run(['combine', shareFiles[2], shareFiles[0]]).stdout, secret);

    const raw = run(['split', '-n', '2', '-k', '2', '--raw'], secret);
    assert.deepEqual(run(['combine'], raw.stdout).stdout, secret);
    const crlf = run(['split', '-n', '2', '-k', '2'], 'text\r\n');
    assert.equal(run(['combine'], crlf.stdout).stdout.toString(), 'text');
    const bareCr = run(['split', '-n', '2', '-k', '2'], 'text\r');
    assert.equal(run(['combine'], bareCr.stdout).stdout.toString(), 'text\r', 'a lone carriage return is data, not a newline');
    const two = run(['split', '-n', '2', '-k', '2'], 'text\n\n');
    assert.equal(run(['combine'], two.stdout).stdout.toString(), 'text\n', 'only one newline is dropped');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('combine reads the JSON share files of the older apps and says they are unverified', () => {
  const fixture = legacy.find((f) => f.format === 'secrets.js' && typeof f.shares[0] === 'object' && f.threshold === 2 && f.text.length > 40);
  const result = run(['combine'], fixture.shares.slice(0, 2).map((share) => JSON.stringify(share)).join('\n'));
  assert.equal(result.status, 0, result.stderr.toString());
  assert.equal(result.stdout.toString(), fixture.text);
  assert.match(result.stderr.toString(), /older format with no integrity check/);
});

test('inspect describes shares and fails on a bad one', () => {
  const shares = run(['split', '-n', '3', '-k', '2'], 's').stdout.toString();
  const good = run(['inspect'], shares);
  assert.equal(good.status, 0);
  const lines = good.stdout.toString().trim().split('\n');
  assert.equal(lines.length, 3);
  assert.deepEqual(JSON.parse(lines[1].slice(3)).index, 2);
  const old = legacy.find((f) => f.format === 'shamir').shares.map((share) => JSON.stringify(share)).join('\n');
  const oldResult = run(['inspect'], old);
  assert.equal(oldResult.status, 0, oldResult.stderr.toString());
  assert.match(oldResult.stdout.toString(), /"format":"shamir"/);
  const bad = run(['inspect'], `${shares.trim()}x\n`);
  assert.equal(bad.status, 1);
  assert.match(bad.stdout.toString(), /"valid":false/);
});

test('mnemonic prints a valid phrase', () => {
  assert.equal(validateMnemonic(run(['mnemonic']).stdout.toString()), true);
  assert.equal(run(['mnemonic', '--words', '24']).stdout.toString().trim().split(' ').length, 24);
  assert.equal(run(['mnemonic', '--words', '13']).status, 1);
});

test('usage errors exit with status 2 and never read a secret from the command line', () => {
  assert.equal(run([]).status, 2);
  assert.equal(run(['--help']).status, 0);
  assert.match(run(['--help']).stdout.toString(), /never taken from the command line/);
  assert.match(run(['--version']).stdout.toString(), /^\d+\.\d+\.\d+\n$/);
  assert.equal(run(['split'], 's').status, 2);
  assert.equal(run(['split', '-n', '3'], 's').status, 2);
  assert.equal(run(['frobnicate']).status, 2);
  assert.equal(run(['split', '--no-such-option']).status, 2);
  const weak = run(['split', '-n', '3', '-k', '1'], 's');
  assert.equal(weak.status, 1);
  assert.match(weak.stderr.toString(), /threshold must be an integer from 2 to 255/);
  assert.equal(run(['combine', '/no/such/file']).status, 1);
  assert.equal(run(['combine'], '').status, 1);
  assert.equal(run(['combine'], 'not a share\n').status, 1);
});
