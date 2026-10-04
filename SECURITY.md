# Security

## What SecretSlices protects against

**Loss.** With a threshold of k out of n shares, the secret survives the loss
of any n - k shares.

**Theft of fewer than k shares.** Such a set contains no information about the
secret beyond an upper bound on its length (its exact length unless `padTo` is
used). This is a property of Shamir's scheme, not of a cipher: it holds
against unlimited computing power and will not weaken with time.

**Mistakes.** A share that is mistyped or cut off is reported, by position.
Shares from different splits, too few shares, and shares that do not fit
together produce an error. `combine` returns the original secret or throws.

## What it does not protect against

**k people cooperating.** Anyone holding k shares has the secret. Choose k
and the holders accordingly.

**Forgery by whoever supplies the whole set.** Shares are not signed and carry
nothing that identifies their dealer. If a single party hands you every share
you combine, they can make you recover any secret they like. The integrity
check catches a wrong share among genuine ones; it does not authenticate a
set. See "What the digest does and does not guarantee" in
[docs/FORMAT.md](docs/FORMAT.md) for the exact statement.

**A holder who refuses.** Any holder can withhold their share, or supply a
bad one, and so block a recovery that needed them. Keep n larger than k.

**The machine you use.** The secret is in memory, and on screen, while you
split or recover it. Malware, a hostile browser extension or someone watching
can take it there. For a valuable secret use a trusted device, offline. The
library clears its working buffers, but JavaScript cannot guarantee that no
copy remains in memory, and strings cannot be cleared at all.

**Timing.** Field arithmetic is written without lookup tables or
secret-dependent branches, but a JavaScript engine gives no constant-time
guarantee. Treat the process that handles the secret as trusted.

**Legacy formats.** `secrets.js`, `shamir` and `sssa` shares have no integrity
check. With a wrong or missing share they can yield a wrong secret without an
error. They are supported for recovery only. The password option of the 2024
app (CryptoJS AES with an MD5-derived key) is weak against password guessing;
it can be decrypted here but not created.

## Assumptions

- `crypto.getRandomValues` is a sound cryptographic random generator. Every
  guarantee above rests on it.
- SHA-256 behaves as a collision-resistant hash (used only for the integrity
  digest and the per-share checksum, never for secrecy).

## Status

This code has not been independently audited. It has an extensive test suite,
including an independent reference decoder, vectors from the original
encoders of every legacy format, and mutation tests; that is evidence, not
proof.

## Reporting a vulnerability

Please email greg@smartledger.technology rather than opening a public issue,
and allow time for a fix before disclosure.
