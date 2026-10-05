# Deploying secretslices.com

The site is one static file, `web/index.html`. There is no server-side code,
no API and no database; the 2024 Express app is not needed.

## Steps

1. Check out a release tag (never a branch) and confirm the file is the one
   the tests built:

       git checkout v1.1.0
       node scripts/build-web.mjs --check
       sha256sum web/index.html

   SHA-256 of `web/index.html` by release:

   | tag | SHA-256 |
   |---|---|
   | v1.1.0 | `6ffee9268c13b91434cef268d45924eb423f80c460ce400597676aba5459613e` |
   | v1.0.0 | `fa3bed21a5cc0948e8336b822672f888630de964ef3add44636b11ae6675e292` |

2. Copy it to the web root as the only file:

       install -D -m 0644 web/index.html /var/www/secretslices/index.html

3. Serve it with [nginx.conf](nginx.conf) and obtain certificates for
   `secretslices.com` and `www.secretslices.com`.

4. DNS: `A` (and `AAAA` if the host has IPv6) records for `@` and `www`
   pointing at the host.

## Checking a deployment

    curl -s https://secretslices.com/ | sha256sum          # equals the value for the deployed tag
    curl -sI https://secretslices.com/ | grep -i -E 'strict-transport|frame-ancestors|x-frame|referrer'
    node scripts/browser-check.mjs https://secretslices.com/   # full end-to-end run in Chrome

Anyone can make the first check: the served page is byte-for-byte the file in
this repository at the tag.

## Updating

Deploy a new tag the same way. `Cache-Control: no-cache` makes browsers
revalidate on every visit, so the new file is picked up at once. The share
format never changes incompatibly, so shares made with any earlier page stay
recoverable.
