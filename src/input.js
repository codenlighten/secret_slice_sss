// Turns whatever a person or program hands over (an array, pasted text, the
// contents of downloaded JSON files) into a flat list of share items.

import { fail } from './errors.js';

// The index just past the JSON object that opens at `start`, or -1. Braces
// inside strings do not count.
function objectEnd(text, start) {
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const char = text[i];
    if (inString) {
      if (char === '\\') i++;
      else if (char === '"') inString = false;
    } else if (char === '"') inString = true;
    else if (char === '{') depth++;
    else if (char === '}' && --depth === 0) return i + 1;
  }
  return -1;
}

function fromText(text) {
  const trimmed = text.trim();
  if (trimmed === '') return [];
  if (trimmed[0] === '[' || trimmed[0] === '{') {
    try {
      return flatten(JSON.parse(trimmed));
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
  }
  // Not one JSON document: JSON objects (the contents of several share files
  // pasted one after another) and bare shares, in any mixture. Everything in
  // the text must be accounted for; nothing is skipped.
  const items = [];
  // A share copied from paper is often typed with the gaps it was printed
  // with, or wrapped over several lines. Every new-format share begins with
  // "ss<version>.", and "." is not in the share alphabet, so a new share can
  // only begin at such a prefix. Pieces after one that are made only of
  // share characters are joined to it; if they were not in fact part of it,
  // the share's checksum fails and the share is reported as damaged.
  const bare = (segment) => {
    let open = false;
    for (const piece of segment.split(/[\s,;"'[\]]+/).filter(Boolean)) {
      if (/^ss\d+\./.test(piece)) {
        items.push(piece);
        open = true;
      } else if (open && /^[A-Za-z0-9_-]+$/.test(piece)) {
        items[items.length - 1] += piece;
      } else {
        items.push(piece);
        open = false;
      }
    }
  };
  let position = 0;
  for (let start = trimmed.indexOf('{'); start !== -1; start = trimmed.indexOf('{', position)) {
    const end = objectEnd(trimmed, start);
    bare(trimmed.slice(position, start));
    try {
      if (end === -1) throw new SyntaxError('unterminated object');
      items.push(...flatten(JSON.parse(trimmed.slice(start, end))));
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      fail('ERR_INVALID_SHARE', 'the input contains JSON that could not be parsed');
    }
    position = end;
  }
  bare(trimmed.slice(position));
  return items;
}

function flatten(input) {
  if (typeof input === 'string') return fromText(input);
  if (Array.isArray(input)) return input.flatMap(flatten);
  if (input !== null && typeof input === 'object') {
    if (typeof input[Symbol.iterator] === 'function') return [...input].flatMap(flatten);
    if (typeof input.value === 'string') return [input];
    if (typeof input.share === 'string') return fromText(input.share);
  }
  fail('ERR_INVALID_SHARE', 'shares must be strings or {part, value} objects');
}

/**
 * @param {unknown} input
 * @returns {(string | {part?: unknown, value: string})[]}
 */
export function collectShares(input) {
  const items = flatten(input);
  if (items.length === 0) fail('ERR_INVALID_ARGUMENT', 'no shares were given');
  return items;
}
