import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { recover } from '../src/index.js';
import { decryptWithPassword, isPasswordEncrypted } from '../src/legacy-password.js';

// Ciphertexts written by CryptoJS 4.2.0, as the 2024 app did.
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/legacy-password.json', import.meta.url), 'utf8'));

test('decrypts secrets that the 2024 app encrypted with a password', async () => {
  assert.ok(fixtures.length >= 4);
  for (const { text, password, ciphertext } of fixtures) {
    assert.equal(isPasswordEncrypted(ciphertext), true);
    assert.equal(await decryptWithPassword(ciphertext, password), text);
    assert.equal(await decryptWithPassword(`  ${ciphertext}\n`, password), text);
  }
});

test('the whole 2024 flow: encrypted, split by the old app, recovered, decrypted', async () => {
  for (const { text, password, shares } of fixtures) {
    const recovered = recover(shares.slice(1)).text();
    assert.equal(isPasswordEncrypted(recovered), true);
    assert.equal(await decryptWithPassword(recovered, password), text);
  }
});

test('a wrong password is rejected', async () => {
  for (const { password, ciphertext } of fixtures) {
    for (const wrong of [`${password}x`, 'nope', password.toUpperCase() + '1']) {
      await assert.rejects(decryptWithPassword(ciphertext, wrong), { code: 'ERR_WRONG_PASSWORD' });
    }
  }
});

test('things that are not encrypted secrets are rejected', async () => {
  for (const text of ['', 'hello', 'witch collapse practice', 'U2FsdGVkX1', 'U2FsdGVkX1 with spaces', 42, null]) {
    assert.equal(isPasswordEncrypted(text), false);
    await assert.rejects(decryptWithPassword(text, 'pw'), { code: 'ERR_INVALID_ARGUMENT' });
  }
  const { ciphertext } = fixtures[0];
  await assert.rejects(decryptWithPassword(ciphertext.slice(0, 24), 'pw'), { code: 'ERR_INVALID_ARGUMENT' });
  await assert.rejects(decryptWithPassword(ciphertext, 5), { code: 'ERR_INVALID_ARGUMENT' });
  await assert.rejects(decryptWithPassword('U2FsdGVkX1AA=', 'pw'), { code: 'ERR_INVALID_ARGUMENT' }, 'matches the pattern but is not valid base64');
  await assert.rejects(decryptWithPassword(`${ciphertext.slice(0, -4)}`, 'pw'), { name: 'SecretSlicesError' });
});
