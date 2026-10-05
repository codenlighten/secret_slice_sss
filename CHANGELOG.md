# Changelog

## 1.1.0

### Web app

- Redesigned around the person recovering a secret, possibly years later and
  under stress. Two plain choices instead of tabs; numbered steps; a plan in
  words before splitting ("Any 3 of them recover the secret, so 2 can be
  lost"); presets for 2 of 3, 3 of 5 and 4 of 7.
- Recovery shows a meter of shares found, and one next action at a time: how
  many more are needed, which line is damaged and what to do about it.
- The secret leaves the screen after a split. A recovered 12 to 24 word
  phrase is laid out as numbered words; the secret can be hidden and shown.
- Shares are displayed and printed in groups of four. Printing gives each
  share its own sheet, with instructions for whoever holds it.
- Larger touch targets, screen-reader announcements for copy and file
  actions, a forced-colours style, one clear message when the threshold
  exceeds the number of shares. Checked in Chromium, Firefox and WebKit.
- The page's statements were tightened: older share formats are recovered but
  not checked; a share shows the secret's length unless it is hidden; copies
  and downloads go to the clipboard and disk.

### Library and command line

- Whitespace inside an `ss1` share is ignored, so a share typed back from
  paper in groups, or wrapped over several lines, is read correctly by
  `combine`, `recover`, `validate`, `inspect` and the command line. The share
  format itself is unchanged.

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
