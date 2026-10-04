# The ss1 share format

This is the complete specification of the shares written by `split()`. It is
meant to be sufficient to write an independent decoder. The format is frozen:
a future incompatible format will use a different prefix (`ss2.`), and
`secretslices` will keep reading `ss1.` shares.

## Text form

    share-text = "ss1." base64url(share-bytes)

`base64url` is RFC 4648 section 5 without `=` padding. A decoder must reject
characters outside the alphabet and a final character with non-zero unused
bits, so every byte string has exactly one accepted spelling. Surrounding
whitespace is ignored.

## Binary form

| offset | size | field       | meaning                                         |
|-------:|-----:|-------------|-------------------------------------------------|
| 0      | 1    | `threshold` | shares needed to recover, 2 to 255              |
| 1      | 1    | `index`     | this share's x coordinate, 1 to 255             |
| 2      | 8    | `setId`     | random; identical in all shares of one split    |
| 10     | n    | `body`      | the shared bytes, n >= 17                       |
| 10 + n | 4    | `checksum`  | detects a damaged share                         |

    checksum = first 4 bytes of SHA-256( "secretslices/v1/share" 0x00 || bytes[0 .. 10+n) )

The checksum is public and unkeyed. It catches typing and copying mistakes
and tells the user *which* share is damaged. It is not a defence against a
deliberate change; the digest below is.

## The shared payload

    padded  = secret || 0x80 || 0x00 * z        z >= 0 chosen so that len(padded) is a multiple of padTo
    digest  = first 16 bytes of SHA-256( "secretslices/v1/secret" 0x00 || threshold || setId || secret )
    payload = digest || padded                  n = len(payload)

`padTo` defaults to 1 (z = 0), and then a share reveals the secret's exact
length, n - 17. With a larger `padTo` a share reveals only
`len(padded) = ceil((len(secret) + 1) / padTo) * padTo`, so the secret's length
is somewhere from `len(padded) - padTo` to `len(padded) - 1`. (The marker byte
needs room: a secret of exactly `padTo` bytes occupies two blocks.)

A string secret is its UTF-8 encoding. A string with an unpaired surrogate is
rejected, because it has no UTF-8 encoding.

## Sharing

Arithmetic is in GF(2^8) with the AES reduction polynomial
x^8 + x^4 + x^3 + x + 1 (0x11b). Addition is XOR.

For each byte position i of the payload, independently:

    f_i(x) = payload[i] + c_{i,1} x + ... + c_{i,threshold-1} x^(threshold-1)

where every coefficient `c` is an independent uniformly random byte (zero is
allowed, including for the highest coefficient). The share with index x has
`body[i] = f_i(x)`. Indices are 1, 2, ..., shares.

## Recovery

1. Decode each share and verify its checksum.
2. All shares must have the same `setId`, `threshold` and body length. Exact
   repeats are ignored; two different shares with the same index are an error.
3. There must be at least `threshold` distinct shares.
4. Interpolate every byte position at x = 0 using all the distinct shares.
5. Strip trailing 0x00 bytes of `padded`; the byte before them must be 0x80.
   What precedes it is the candidate secret.
6. Recompute `digest` from the candidate secret and compare it with
   `payload[0 .. 16)` in constant time. If they differ, fail.

## What the digest does and does not guarantee

The digest is a consistency check on the reconstructed secret. It is not a
signature, and shares are not authenticated.

Fewer than `threshold` shares reveal nothing about the payload, digest
included, so the digest gives no way to test guesses of a low-entropy secret.

Recovery fails the digest check, except with probability about 2^-128, when:

* a share is damaged in a way its checksum missed, or belongs to another
  split, or
* too few genuine shares are combined (for example after their headers were
  edited to claim a lower threshold), or
* someone alters or fabricates shares, and the set being combined also
  contains at least one genuine share that this person has not seen, and they
  do not know the secret. The result then depends on a value they cannot
  predict, and fixing up the digest would require knowing the secret.

Recovery can be made to succeed with a **different** secret by:

* anyone who supplies *every* share used in the recovery. Nothing ties a set
  of shares to the original dealer, so a complete set for any secret can be
  made by anyone, including a set that reuses a genuine `setId`;
* anyone who knows the secret (any `threshold` holders together, or the
  dealer) and supplies at least one of the shares used.

So: when recovering, take shares from the people you gave them to, and do not
accept a whole set from a single source you do not trust. Authenticating the
original secret needs something this format does not contain, such as a
commitment published at split time.

A holder can always make recovery *fail* by withholding a share or supplying
a bad one. Recovery uses every share it is given and does not search for a
good subset, so keep more shares than the threshold: recovery then remains
possible by leaving the missing or bad share out. A share damaged by accident
is reported by its checksum; a deliberately bad share is not identified.
