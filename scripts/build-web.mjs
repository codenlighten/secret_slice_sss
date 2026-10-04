// Builds web/index.html: the whole SecretSlices app in ONE self-contained file
// that works from a local disk with no network access.
//
//   node scripts/build-web.mjs           write web/index.html
//   node scripts/build-web.mjs --check   fail if web/index.html is out of date
//
// This is deliberately a small bundler of our own rather than a dependency:
// the file people trust with their secrets is then built by nothing but Node
// and the code in this repository. It understands exactly the import/export
// forms used in src/ and web/ and refuses anything else.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const IMPORT = /^import\s+(?:\{([^}]*)\}|\*\s+as\s+(\w+))\s+from\s+'(\.[^']+)';[ \t]*$/gm;
const EXPORT_DECLARATION = /^export\s+((?:async\s+)?function\*?|const|let|class)\s+(\w+)/gm;
const EXPORT_LIST = /^export\s+\{([^}]*)\};[ \t]*$/gm;

function transform(file, modules) {
  const id = relative(root, file);
  if (modules.has(id)) return id;
  modules.set(id, null); // reserve the slot: dependencies must come first
  let code = readFileSync(file, 'utf8').replace(/^#!.*\n/, '');
  const names = [];

  code = code.replace(IMPORT, (_, list, namespace, specifier) => {
    const dependency = transform(resolve(dirname(file), specifier), modules);
    const target = namespace ?? `{ ${list.split(',').map((name) => name.trim()).filter(Boolean)
      .map((name) => name.replace(/\s+as\s+/, ': ')).join(', ')} }`;
    return `const ${target} = __modules[${JSON.stringify(dependency)}];`;
  });
  code = code.replace(EXPORT_DECLARATION, (_, kind, name) => {
    names.push(name);
    return `${kind} ${name}`;
  });
  code = code.replace(EXPORT_LIST, (_, list) => {
    names.push(...list.split(',').map((name) => name.trim()).filter(Boolean));
    return '';
  });

  const leftover = /^\s*(import|export)\b.*$/m.exec(code);
  if (leftover) throw new Error(`${id}: unsupported module syntax: ${leftover[0].trim()}`);

  modules.delete(id);
  modules.set(id, `__modules[${JSON.stringify(id)}] = (() => {\n${code}\nreturn { ${names.join(', ')} };\n})();\n`);
  return id;
}

/**
 * Bundles an ES module and everything it imports into one classic script.
 * The script's completion value is the entry module's exports.
 * @param {string} entry path relative to the repository root
 * @returns {string}
 */
export function bundle(entry) {
  const modules = new Map();
  const id = transform(join(root, entry), modules);
  return `(() => {\n'use strict';\nconst __modules = Object.create(null);\n${[...modules.values()].join('\n')}\nreturn __modules[${JSON.stringify(id)}];\n})();\n`;
}

const sri = (text) => `sha256-${createHash('sha256').update(text).digest('base64')}`;

/** @returns {string} the complete web/index.html */
export function buildPage() {
  const template = readFileSync(join(root, 'web/template.html'), 'utf8');
  const style = readFileSync(join(root, 'web/style.css'), 'utf8');
  const script = bundle('web/app.js');
  if (script.includes('</script')) throw new Error('the bundle contains "</script", which would end the inline script early');
  const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const csp = `default-src 'none'; script-src '${sri(script)}'; style-src '${sri(style)}'; img-src data:; base-uri 'none'; form-action 'none'`;
  const fill = { CSP: csp, STYLE: style, SCRIPT: script, VERSION: version };
  const page = template.replace(/<!--%(\w+)%-->|\/\*%(\w+)%\*\//g, (match, a, b) => {
    const key = a ?? b;
    if (!(key in fill)) throw new Error(`unknown placeholder ${match}`);
    return fill[key];
  });
  return page;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const output = join(root, 'web/index.html');
  const page = buildPage();
  if (process.argv.includes('--check')) {
    let current = '';
    try { current = readFileSync(output, 'utf8'); } catch { /* missing counts as stale */ }
    if (current !== page) {
      console.error('web/index.html is out of date; run: npm run build');
      process.exit(1);
    }
    console.log('web/index.html is up to date');
  } else {
    writeFileSync(output, page);
    console.log(`wrote web/index.html (${(page.length / 1024).toFixed(1)} kB)`);
  }
}
