# SecretSlices

Split a secret into shares. Any chosen number of them recover it; fewer reveal
nothing.

SecretSlices is [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
with **verified recovery**: combining shares either returns the original
secret or throws an error that says what is wrong. It never returns garbage.

- A library for Node.js and browsers, with **no dependencies**.
- A command-line tool.
- A [single-file web app](web/index.html) that works offline — the app behind
  [secretslices.com](https://secretslices.com).
- Reads the shares of **every earlier version** of SecretSlices.

```js
import { split, combineText } from 'secretslices';

const shares = split('witch collapse practice feed shame open despair creek road again ice least',
                     { shares: 5, threshold: 3 });
// [ 'ss1.AwFhSSNI0cch2pdMewSlJr…', 'ss1.AwJhSSNI0cch2imDlrDY…', … ]   five strings

combineText([shares[4], shares[0], shares[2]]);   // any three, any order
// 'witch collapse practice feed shame open despair creek road again ice least'

combineText([shares[0], shares[1]]);
// SecretSlicesError [ERR_INSUFFICIENT_SHARES]: this secret needs 3 different shares, but only 2 were given
```

## Install

```sh
npm install secretslices
```

Requires Node.js 20.19 or later. The package is ES modules; `require('secretslices')`
also works from CommonJS on those Node versions. Bundlers (esbuild, Vite,
webpack) can bundle it for browsers as it is.

## Library

### `split(secret, { shares, threshold, padTo? })` → `string[]`

`secret` is a string (stored as UTF-8) or a `Uint8Array`, of any length
including empty. `shares` is 2 to 255; `threshold` is 2 to `shares`.

A share is 31 bytes longer than the secret, so a share reveals the secret's
length. Pass `padTo: 64` (for example) to round the length up to a multiple
of 64 bytes and hide it.

A threshold of 1 is refused: every share would simply be the secret.

### `combine(shares)` → `Uint8Array`, `combineText(shares)` → `string`

Takes at least `threshold` shares in any order. Extra shares and exact
repeats are fine, and so is whitespace inside a share (one typed back from
paper in groups, say). Throws a `SecretSlicesError` if the result cannot be
verified.

### `recover(input)` → `{ secret, format, verified, text() }`

Like `combine`, but accepts **any format SecretSlices has ever produced** and
any reasonable way of handing shares over: an array, pasted text with one
share per line, or the JSON files written by the 2024 app.

`verified` is `true` only for current (`ss1`) shares. The older formats have
no integrity check, so with a wrong share they can return a wrong secret;
re-split anything recovered from them.

### `validate(share)` → `{ valid, format, … }` or `{ valid: false, code, message }`

Checks a single share, in any supported format, without the others. **Never
throws**, whatever it is given — suitable for checking a share before storing
it.

### `inspect(share)` → `{ format, threshold, index, setId, maxSecretBytes }`

Describes one `ss1` share. Throws if it is damaged.

### Errors

Every failure is a `SecretSlicesError` with a stable `code`:

| code | meaning |
|---|---|
| `ERR_INVALID_ARGUMENT` | bad arguments, such as a threshold below 2 |
| `ERR_INVALID_SHARE` | not a share, or a malformed one (`shareIndex` says which) |
| `ERR_SHARE_CHECKSUM` | a share was mistyped, cut off or altered (`shareIndex` says which) |
| `ERR_UNSUPPORTED_VERSION` | a share from a newer format; upgrade the library |
| `ERR_MIXED_SHARES` | shares from different splits or different formats |
| `ERR_DUPLICATE_SHARE` | two different shares claim the same number |
| `ERR_INSUFFICIENT_SHARES` | too few shares (`required`, `provided`) |
| `ERR_INTEGRITY` | the shares do not reconstruct a valid secret |
| `ERR_INVALID_UTF8` | the secret is binary, but text was asked for |

### Other entry points

```js
import { generateMnemonic, validateMnemonic } from 'secretslices/mnemonic';        // BIP-39 phrases
import { decryptWithPassword, isPasswordEncrypted } from 'secretslices/legacy-password';
import { parseLegacyShare, combineLegacyShares } from 'secretslices/legacy';
```

TypeScript declarations are included.

## Command line

```sh
echo 'my secret' | npx secretslices split -n 5 -k 3 > shares.txt
head -3 shares.txt | npx secretslices combine
npx secretslices inspect shares.txt
npx secretslices mnemonic
```

The secret is read from standard input or a file, never from the command
line, where other users of the machine could see it. `secretslices --help`
has the details.

## Web app

[`web/index.html`](web/index.html) is the whole app in one file of about 95 kB: open it
from disk, or serve it from any static host. It generates recovery phrases,
splits, prints each share on its own sheet with instructions, and recovers — including shares and
password-protected secrets from the 2024 secretslices.com.

Its Content-Security-Policy is `default-src 'none'` with the exact script and
style pinned by hash, so the page is unable to make a network request even if
it had a bug. `npm run test:browser` proves that in a real Chrome.

The file is generated by `npm run build` from `web/` and `src/` using only
Node; the test suite fails if the committed file is out of date.

## Share formats

New shares are always `ss1`, specified completely in
[docs/FORMAT.md](docs/FORMAT.md). It is Shamir's scheme over GF(2⁸) on every
byte of the secret, with a digest shared alongside the secret so that recovery
can be verified, and a checksum on each share so that a typo is reported
against the share that has it.

| format | written by | read by `recover` |
|---|---|---|
| `ss1` | this library, 1.0 onwards | yes, verified |
| `secrets.js` | secretslices.com browser app, 2024 (`{"part": 1, "value": "801…"}`) | yes |
| `shamir` | secretslices.com server API, 2024 (`{"part": "1", "value": "12,240,…"}`) | yes |
| `sssa` | SSSaaS/sssa-js 0.0.1, which this repository started from | yes |

A format, once shipped, is never dropped. The decoders are tested against
shares produced by the original encoders, not by this library
(`scripts/make-fixtures.mjs`).

## Security

Read [SECURITY.md](SECURITY.md) before relying on this for something that
matters. In short:

- Fewer than `threshold` shares reveal nothing about the secret but a bound on
  its length. This is information-theoretic: it does not depend on any
  computational assumption.
- Recovery detects damaged, mismatched and insufficient shares. Shares are
  **not signed**: do not accept a complete set from one untrusted source.
- This implementation has not had an independent security audit.

## Development

```sh
npm test               # no dependencies to install, runs offline
npm run build          # regenerate web/index.html
npm run test:browser   # end-to-end check in headless Chrome
```

## History and credits

SecretSlices was created by Gregory J. Ward (SmartLedger) in 2024. Version 1.0
is a complete rewrite. The repository began as a fork of
[SSSaaS/sssa-js](https://github.com/SSSaaS/sssa-js) by Alexander Scheel, Joel
May and Matthew Burket, whose share format is still readable. The BIP-39 word
list is from the [Bitcoin BIPs repository](https://github.com/bitcoin/bips).

MIT licence; see [LICENSE](LICENSE).
