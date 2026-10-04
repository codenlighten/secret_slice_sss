# Changelog

## 1.0.0

A complete rewrite. Nothing of the 0.0.1 code (SSSaaS/sssa-js) remains, but its
shares can still be recovered.

### Added

- The `ss1` share format (docs/FORMAT.md): Shamir's scheme over GF(2^8) on
  bytes, with verified recovery, a per-share checksum, a set identifier, and
  the threshold recorded in each share.
- `split`, `combine`, `combineText`, `recover`, `validate`, `inspect`.
- `recover` reads every format SecretSlices has shipped: the 2024
  secretslices.com browser shares (secrets.js), the 2024 server API shares
  (`shamir`), and sssa-js shares. `secretslices/legacy-password` decrypts
  secrets that the 2024 app protected with a password.
- Binary secrets (`Uint8Array`), empty secrets, and optional length hiding
  (`padTo`).
- `secretslices/mnemonic`: BIP-39 phrase generation and validation.
- A command-line tool, `secretslices`.
- A single-file offline web app, `web/index.html`.
- TypeScript declarations.

### Fixed, relative to 0.0.1

- A threshold of 0 or 1 was accepted and put the secret, readable, in every share.
- Wrong, damaged, repeated or insufficient shares produced garbage, an
  unrelated exception, or `undefined`; now each has its own error.
- Secrets ending in NUL bytes were silently truncated; an empty secret could
  not be recovered; a non-string secret silently produced no shares.
- The check for repeated x coordinates never ran, and a zero coordinate was
  not excluded.
- The test runner exited with status 0 when a test failed.
- The committed browser bundles were older than the source.
- An undeclared global variable; unconditional use of `module` and `global`.

### Removed

- All four runtime dependencies, and both build dependencies.
- `sssa.create` / `sssa.combine`. Use `split` / `recover`. New shares are not
  readable by the SSSaaS libraries for other languages.
