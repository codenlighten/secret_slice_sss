# IP registrations

Evidence of authorship registered through [iptrust.org](https://iptrust.org).
A record is evidence that the committed content existed by the time of the
anchoring block and that the signer made the statement; it does not itself
create or register any right.

| date | covers | type | record | signer | git tag |
|---|---|---|---|---|---|
| 2026-10-04 | SecretSlices 1.0: library, command-line tool, single-file web app, ss1 share format and its specification (48 files) | software | [`6c5eb6b5305fdc8ff7ad6a09c19e9cfd1f54ce1994f80bfde4356e279d548bdc`](https://iptrust.org/v/6c5eb6b5305fdc8ff7ad6a09c19e9cfd1f54ce1994f80bfde4356e279d548bdc) | Gregory J. Ward | `ip-2026-10-04` |

Authors: Gregory J. Ward, Bryan W. Daugherty, Shawn M. Ryan.

The registered tree includes one third-party item, the BIP-39 English word
list (`src/bip39-english.js`, also embedded in `web/index.html`), which is
attributed in the file and is not claimed as original.

## Verifying

The record commits to the tree at the tag. Verification needs the private
evidence in `.iptrust/`, which is kept out of this public repository. With it
in place, verify in a separate worktree so the working copy is not touched:

```sh
git worktree add /tmp/at-tag-secretslices ip-2026-10-04 && cp -r .iptrust /tmp/at-tag-secretslices/
(cd /tmp/at-tag-secretslices && iptrust2 verify 6c5eb6b5305fdc8ff7ad6a09c19e9cfd1f54ce1994f80bfde4356e279d548bdc --fetch-headers)
git worktree remove --force /tmp/at-tag-secretslices
```

Expect `verdict: valid` and `content: matched`. If `--fetch-headers` fails
with a network error, run it without the flag to check the content match, and
repeat with the flag later.
