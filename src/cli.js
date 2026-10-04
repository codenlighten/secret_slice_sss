#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { SecretSlicesError, recover, split, validate } from './index.js';
import { collectShares } from './input.js';
import { generateMnemonic } from './mnemonic.js';

const USAGE = `Usage:
  secretslices split -n <shares> -k <threshold> [--pad-to <bytes>] [--raw] [file]
  secretslices combine [file ...]
  secretslices inspect [file ...]
  secretslices mnemonic [--words 12|15|18|21|24]

split     Reads a secret from the file, or from standard input, and prints one
          share per line. Any <threshold> of the <shares> recover the secret.
          One trailing newline (LF or CRLF) is dropped from standard input (so that
          "echo secret | secretslices split" does what you expect); use --raw
          to keep every byte. A file is always read exactly.
combine   Reads shares (one per line, or the JSON files of the older
          SecretSlices apps) and writes the secret to standard output.
inspect   Reports what each share is, without needing the others.
mnemonic  Prints a new random BIP-39 phrase.

The secret is never taken from the command line, where other users of the
machine could see it.`;

async function readStdin() {
  if (process.stdin.isTTY) process.stderr.write('Reading from the terminal; finish with Ctrl-D.\n');
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function shareTexts(files) {
  if (files.length === 0) return [(await readStdin()).toString('utf8')];
  return files.map((file) => readFileSync(file, 'utf8'));
}

async function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      shares: { type: 'string', short: 'n' },
      threshold: { type: 'string', short: 'k' },
      'pad-to': { type: 'string' },
      raw: { type: 'boolean' },
      words: { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  const [command, ...files] = positionals;

  if (values.version) {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }
  if (values.help || command === undefined) {
    process.stdout.write(`${USAGE}\n`);
    return values.help ? 0 : 2;
  }

  switch (command) {
    case 'split': {
      if (values.shares === undefined || values.threshold === undefined) {
        process.stderr.write('secretslices: split needs -n <shares> and -k <threshold>\n');
        return 2;
      }
      if (files.length > 1) {
        process.stderr.write('secretslices: split takes at most one file\n');
        return 2;
      }
      let secret = files.length === 0 ? await readStdin() : readFileSync(files[0]);
      if (files.length === 0 && !values.raw) {
        if (secret.at(-1) === 0x0a) secret = secret.subarray(0, secret.at(-2) === 0x0d ? -2 : -1);
      }
      const shares = split(new Uint8Array(secret), {
        shares: Number(values.shares),
        threshold: Number(values.threshold),
        ...(values['pad-to'] === undefined ? {} : { padTo: Number(values['pad-to']) }),
      });
      process.stdout.write(`${shares.join('\n')}\n`);
      return 0;
    }
    case 'combine': {
      const result = recover(await shareTexts(files));
      if (!result.verified) {
        process.stderr.write(`secretslices: these are "${result.format}" shares, an older format with no integrity check; ` +
          'if any share is wrong or too few were given, the output is garbage.\n');
      }
      // Exactly the secret's bytes go to standard output, nothing more. On a
      // terminal, end the line on standard error so the prompt stays tidy.
      process.stdout.write(result.secret);
      if (process.stdout.isTTY) process.stderr.write('\n');
      return 0;
    }
    case 'inspect': {
      let bad = 0;
      const texts = collectShares(await shareTexts(files));
      texts.forEach((share, i) => {
        const info = validate(share);
        if (!info.valid) bad++;
        process.stdout.write(`${i + 1}: ${JSON.stringify(info)}\n`);
      });
      return bad === 0 ? 0 : 1;
    }
    case 'mnemonic':
      process.stdout.write(`${generateMnemonic(values.words === undefined ? 12 : Number(values.words))}\n`);
      return 0;
    default:
      process.stderr.write(`secretslices: unknown command "${command}"\n\n${USAGE}\n`);
      return 2;
  }
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error) {
  if (error instanceof SecretSlicesError || error.code === 'ENOENT' || error.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION' || error instanceof SyntaxError) {
    process.stderr.write(`secretslices: ${error.message}\n`);
    process.exitCode = error.code?.startsWith?.('ERR_PARSE_ARGS') ? 2 : 1;
  } else {
    throw error;
  }
}
