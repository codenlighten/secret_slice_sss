// Turns whatever a person or program hands over (an array, pasted text, the
// contents of downloaded JSON files) into a flat list of share items.

import { fail } from './errors.js';

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
  const bare = (segment) => items.push(...segment.split(/[\s,;"'[\]]+/).filter(Boolean));
  let position = 0;
  for (const match of trimmed.matchAll(/\{[^{}]*\}/g)) {
    bare(trimmed.slice(position, match.index));
    try {
      items.push(...flatten(JSON.parse(match[0])));
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
      fail('ERR_INVALID_SHARE', 'the input contains JSON that could not be parsed');
    }
    position = match.index + match[0].length;
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
