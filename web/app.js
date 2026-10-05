import { SecretSlicesError, combine, inspect, recover, split, validate } from '../src/index.js';
import { collectShares } from '../src/input.js';
import { decryptWithPassword, isPasswordEncrypted } from '../src/legacy-password.js';
import { generateMnemonic, validateMnemonic } from '../src/mnemonic.js';

const PAD_TO = 64;
const $ = (id) => document.getElementById(id);
const message = (error) => (error instanceof SecretSlicesError ? error.message : `Unexpected error: ${error?.message ?? error}`);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

function show(element, text) {
  element.textContent = text ?? '';
  element.hidden = !text;
}

// Spoken by a screen reader without moving anything on the page.
function say(text) {
  $('say').textContent = '';
  setTimeout(() => { $('say').textContent = text; }, 30);
}

async function copy(text, button, what) {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
    say(`${what} copied.`);
  } catch {
    button.textContent = 'Select the text and copy it';
    say('Copying is not available here. Select the text and copy it.');
  }
  setTimeout(() => { button.textContent = original; }, 1800);
}

function download(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

// Fills an element with one child per entry, each given a class or none.
function marks(element, count, filled, className) {
  element.replaceChildren();
  for (let i = 0; i < count; i++) {
    const mark = document.createElement('i');
    if (i < filled) mark.className = className;
    element.append(mark);
  }
}

// ----------------------------------------------------------------------- tabs

const tabs = [$('tab-split'), $('tab-recover')];
function select(tab) {
  for (const other of tabs) {
    const selected = other === tab;
    other.setAttribute('aria-selected', String(selected));
    other.tabIndex = selected ? 0 : -1;
    $(other.getAttribute('aria-controls')).hidden = !selected;
  }
}
for (const tab of tabs) {
  tab.addEventListener('click', () => select(tab));
  tab.addEventListener('keydown', (event) => {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
    event.preventDefault();
    const next = tabs[(tabs.indexOf(tab) + 1) % tabs.length];
    select(next);
    next.focus();
  });
}

// ---------------------------------------------------------------------- split

let currentShares = [];

function describeSecret() {
  const text = $('secret').value.trim();
  const words = text.split(/\s+/);
  const hint = $('secret-hint');
  hint.className = 'hint';
  if ([12, 15, 18, 21, 24].includes(words.length) && words.every((word) => /^[a-z]+$/.test(word))) {
    if (validateMnemonic(text)) {
      hint.textContent = `Valid ${words.length}-word recovery phrase`;
      hint.classList.add('ok');
    } else {
      hint.textContent = 'This looks like a recovery phrase, but a word is misspelled or out of place. Check it before splitting.';
      hint.classList.add('bad');
    }
  } else {
    hint.textContent = '';
  }
}

// What the two numbers mean, said before anything is split: how many there
// will be, how many it takes, how many can be lost, and when a choice leaves
// no room for losing any.
const MAX_DOTS = 24;
const GROUP_UP_TO = 600;
function describePlan() {
  const shares = Number($('shares').value);
  const threshold = Number($('threshold').value);
  const sharesField = $('shares');
  const thresholdField = $('threshold');
  sharesField.setCustomValidity('');
  thresholdField.setCustomValidity('');
  for (const preset of document.querySelectorAll('.preset')) {
    preset.setAttribute('aria-pressed', String(Number(preset.dataset.shares) === shares && Number(preset.dataset.threshold) === threshold));
  }
  const plan = $('plan');
  const whole = (n) => Number.isInteger(n) && n >= 2 && n <= 255;
  plan.className = 'plan';
  if (!whole(shares) || !whole(threshold)) {
    $('plan-dots').replaceChildren();
    $('plan-text').textContent = 'Choose how many shares to make and how many it should take, each from 2 to 255.';
    return;
  }
  if (threshold > shares) {
    thresholdField.setCustomValidity(`You are making ${shares} shares, so at most ${shares} can be required.`);
    $('plan-dots').replaceChildren();
    $('plan-text').textContent = `You cannot require ${threshold} shares when only ${shares} are made. Make more, or require fewer.`;
    plan.classList.add('risky');
    return;
  }
  if (shares <= MAX_DOTS) marks($('plan-dots'), shares, threshold, 'need'); else $('plan-dots').replaceChildren();
  const spare = shares - threshold;
  $('plan-text').textContent = spare === 0
    ? `${shares} shares will be made, and all ${shares} are needed to recover the secret. If even one is lost, the secret is lost. ${threshold - 1} or fewer reveal nothing.`
    : `${shares} shares will be made. Any ${threshold} of them recover the secret, so ${spare === 1 ? 'one can be lost' : `${spare} can be lost`}. ${threshold - 1} or fewer reveal nothing.`;
  if (spare === 0) plan.classList.add('risky');
}

function shareFileName(info, total) {
  return `secretslices-${info.setId.slice(0, 6)}-share-${info.index}-of-${total}.txt`;
}

// The share's text in groups of four. No whitespace is added between the
// groups, so the element's text, and what is copied from it, is the share.
function grouped(element, share) {
  element.replaceChildren();
  // A share long enough that nobody will type it is left whole: thousands of
  // groups would cost more to draw than they could ever help.
  if (share.length > GROUP_UP_TO) { element.textContent = share; return; }
  for (let i = 0; i < share.length; i += 4) {
    const group = document.createElement('span');
    group.textContent = share.slice(i, i + 4);
    element.append(group);
  }
}

function clearSplit() {
  currentShares = [];
  $('secret').value = '';
  $('share-list').replaceChildren();
  $('split-result').hidden = true;
  $('split-form').hidden = false;
  show($('split-error'));
  describeSecret();
  describePlan();
}

$('secret').addEventListener('input', describeSecret);
$('generate').addEventListener('click', () => {
  $('secret').value = generateMnemonic(12);
  describeSecret();
});
$('shares').addEventListener('input', () => {
  $('threshold').max = $('shares').value || 255;
  describePlan();
});
$('threshold').addEventListener('input', describePlan);
for (const preset of document.querySelectorAll('.preset')) {
  preset.addEventListener('click', () => {
    $('shares').value = preset.dataset.shares;
    $('threshold').max = preset.dataset.shares;
    $('threshold').value = preset.dataset.threshold;
    describePlan();
  });
}

$('split-form').addEventListener('submit', (event) => {
  event.preventDefault();
  show($('split-error'));
  $('split-result').hidden = true;
  const secret = $('secret').value;
  const shares = Number($('shares').value);
  const threshold = Number($('threshold').value);
  try {
    if (secret === '') throw new SecretSlicesError('ERR_INVALID_ARGUMENT', 'Enter a secret to split.');
    currentShares = split(secret, { shares, threshold, ...($('pad').checked ? { padTo: PAD_TO } : {}) });
    // Prove to the user, before they rely on it, that these shares work:
    // recover from the last `threshold` shares and compare.
    const check = new TextDecoder().decode(combine(currentShares.slice(-threshold)));
    if (check !== secret) throw new Error('self-check failed; do not use these shares');
  } catch (error) {
    currentShares = [];
    $('split-form').hidden = false;
    show($('split-error'), message(error));
    return;
  }

  const list = $('share-list');
  list.replaceChildren();
  currentShares.forEach((share) => {
    const info = inspect(share);
    const item = $('share-template').content.firstElementChild.cloneNode(true);
    item.querySelector('.share-title').textContent = `Share ${info.index} of ${shares}`;
    item.querySelector('.share-note').textContent = `any ${threshold} recover the secret · set ${info.setId.slice(0, 6)} · secretslices.com`;
    // Printed on the share's own sheet, for whoever holds it.
    item.querySelector('.share-what').textContent = `This is one of ${shares} shares of a secret. Any ${threshold} of them, brought together, recover it. ${threshold - 1} or fewer reveal nothing.`;
    grouped(item.querySelector('.share-text'), share);
    item.querySelector('.copy').addEventListener('click', (e) => copy(share, e.currentTarget, `Share ${info.index}`));
    item.querySelector('.download').addEventListener('click', () => download(shareFileName(info, shares), `${share}\n`));
    list.append(item);
  });
  $('split-summary').textContent = `${shares} shares created. Any ${threshold} of them recover the secret; ${threshold - 1} or fewer reveal nothing. Checked: they work.`;
  // The secret has done its work: it leaves the screen, and what is left is
  // the shares and what to do with them.
  $('split-form').hidden = true;
  $('split-result').hidden = false;
  $('split-summary').focus();
});

$('edit-split').addEventListener('click', () => {
  $('split-form').hidden = false;
  $('split-result').hidden = true;
  $('secret').focus();
});
$('download-all').addEventListener('click', () => {
  currentShares.forEach((share, i) => {
    // Browsers block a burst of downloads; space them out.
    setTimeout(() => download(shareFileName(inspect(share), currentShares.length), `${share}\n`), i * 250);
  });
});
$('print').addEventListener('click', () => window.print());
$('clear-split').addEventListener('click', () => { const held = document.activeElement === $('clear-split'); clearSplit(); if (held) $('secret').focus(); });

// -------------------------------------------------------------------- recover

// What to do about one share that cannot be read, said after what is wrong
// with it. A person recovering a secret may be doing it once in their life.
const REPAIR = {
  ERR_SHARE_CHECKSUM: 'Compare it with the original, one group at a time.',
  ERR_INVALID_SHARE: 'Compare it with the original: a character is wrong, or part of it is missing.',
  ERR_UNSUPPORTED_VERSION: 'It was made by a newer SecretSlices. Use the newest copy of this page.',
};

function describeShares() {
  const status = $('share-status');
  const next = $('recover-next');
  const meter = $('share-meter');
  status.replaceChildren();
  meter.hidden = true;
  next.className = 'next';
  show($('recover-error'));
  const text = $('shares-in').value;
  if (text.trim() === '') {
    next.textContent = 'Nothing added yet. Each share you add is checked here as you go.';
    return;
  }

  let items;
  try {
    items = collectShares(text);
  } catch (error) {
    show($('recover-error'), message(error));
    next.textContent = '';
    return;
  }
  const sets = new Map();
  const line = (content, className) => {
    const item = document.createElement('li');
    item.textContent = content;
    if (className) item.className = className;
    status.append(item);
  };
  let broken = 0;
  let repair = '';
  items.forEach((item, i) => {
    const info = validate(item);
    if (!info.valid) {
      line(`Share ${i + 1}: ${info.message}`, 'bad');
      broken += 1;
      repair ||= `Line ${i + 1} is not a usable share. ${REPAIR[info.code] ?? REPAIR.ERR_INVALID_SHARE}`;
    } else if (info.format === 'ss1') {
      const set = sets.get(info.setId) ?? { threshold: info.threshold, indexes: new Set() };
      set.indexes.add(info.index);
      sets.set(info.setId, set);
    } else {
      const set = sets.get(info.format) ?? { indexes: new Set() };
      set.indexes.add(info.index ?? i);
      sets.set(info.format, set);
    }
  });
  if (sets.size > 1) line('These shares come from different secrets and cannot be combined.', 'bad');
  let ready = false;
  let legacy = false;
  let missing = 0;
  for (const [id, set] of sets) {
    const count = set.indexes.size;
    if (set.threshold === undefined) {
      // Never marked as enough: an older share does not say how many are needed.
      line(`${count} ${count === 1 ? 'share' : 'shares'} in an older SecretSlices format.`);
      legacy = true;
    } else if (count >= set.threshold) {
      line(`${count} of the ${set.threshold} shares needed (set ${id.slice(0, 6)}). Ready to recover.`, 'ok');
      ready = true;
    } else {
      line(`${count} of the ${set.threshold} shares needed (set ${id.slice(0, 6)}). Add ${set.threshold - count} more.`);
      missing = set.threshold - count;
    }
    if (sets.size === 1 && set.threshold !== undefined) {
      marks(meter, set.threshold, Math.min(count, set.threshold), 'have');
      meter.hidden = set.threshold > MAX_DOTS;
      line(`Found: ${[...set.indexes].sort((a, b) => a - b).map((index) => `share ${index}`).join(', ')}.`);
    }
  }

  // One instruction, the most useful one, said last.
  if (sets.size > 1) {
    next.textContent = 'Keep only the shares that belong together. Each share is printed with a short set code, and shares of the same secret have the same code.';
    next.classList.add('fix');
  } else if (broken > 0) {
    next.textContent = repair;
    next.classList.add('fix');
  } else if (ready) {
    next.textContent = 'You have enough. Choose Recover the secret.';
    next.classList.add('ready');
  } else if (missing > 0) {
    next.textContent = `You need ${plural(missing, 'more share')}. Any of the other shares of this secret will do.`;
  } else if (legacy) {
    // An older share does not say how many are needed, so nothing here can
    // promise that these are enough.
    next.textContent = 'Older shares do not say how many are needed. Add every one you have, then choose Recover the secret.';
  } else {
    next.textContent = 'Add another share.';
  }
}

function clearRecover() {
  $('shares-in').value = '';
  $('recovered').textContent = '';
  $('recovered-words').replaceChildren();
  $('recovered-words').hidden = true;
  $('password').value = '';
  $('recover-result').hidden = true;
  $('recover-form').hidden = false;
  $('password-form').hidden = true;
  show($('password-error'));
  conceal(false);
  describeShares();
}

async function addFiles(files) {
  const box = $('shares-in');
  for (const file of files) {
    const text = (await file.text()).trim();
    box.value = box.value.trim() === '' ? text : `${box.value.trim()}\n${text}`;
  }
  describeShares();
  say(`${plural(files.length, 'file')} added.`);
}

// Shows the recovered text. A recovery phrase is also laid out as numbered
// words, which is how it has to be copied out or typed in somewhere else.
function reveal(text) {
  $('recovered').textContent = text;
  const words = text.trim().split(/\s+/);
  const list = $('recovered-words');
  list.replaceChildren();
  const phrase = [12, 15, 18, 21, 24].includes(words.length) && words.every((word) => /^[a-z]+$/.test(word)) && validateMnemonic(text.trim());
  if (phrase) {
    for (const word of words) {
      const item = document.createElement('li');
      item.textContent = word;
      list.append(item);
    }
  }
  list.hidden = !phrase;
  conceal(false);
}

function conceal(hide) {
  const button = $('toggle-secret');
  button.setAttribute('aria-pressed', String(hide));
  button.textContent = hide ? 'Show it' : 'Hide it';
  $('recovered').hidden = hide;
  $('recovered-words').hidden = hide || $('recovered-words').childElementCount === 0;
}

$('shares-in').addEventListener('input', describeShares);
$('files').addEventListener('change', async (event) => {
  await addFiles(event.target.files);
  event.target.value = '';
});
for (const type of ['dragenter', 'dragover', 'dragleave', 'drop']) {
  $('shares-in').addEventListener(type, (event) => {
    if (!event.dataTransfer?.types.includes('Files')) return;
    event.preventDefault();
    event.currentTarget.classList.toggle('dragging', type === 'dragenter' || type === 'dragover');
    if (type === 'drop') addFiles(event.dataTransfer.files);
  });
}

$('recover-form').addEventListener('submit', (event) => {
  event.preventDefault();
  show($('recover-error'));
  $('recover-result').hidden = true;
  $('password-form').hidden = true;
  show($('password-error'));
  let result;
  let text;
  try {
    result = recover($('shares-in').value);
    text = result.text();
  } catch (error) {
    show($('recover-error'), error?.code === 'ERR_INVALID_UTF8' && result && !result.verified
      ? 'These shares do not produce a readable secret. At least one is wrong, or more are needed.'
      : message(error));
    $('recover-form').hidden = false;
    return;
  }
  reveal(text);
  $('recover-summary').textContent = result.verified ? 'Secret recovered and verified' : 'Secret recovered';
  show($('recover-warning'), result.verified ? '' :
    'These shares are in an older format that cannot be verified. If the text below looks wrong, a share is incorrect or more shares are needed. Consider splitting the secret again to get verifiable shares.');
  $('password-form').hidden = !isPasswordEncrypted(text);
  // The shares have done their work: what is left on screen is the secret
  // and what to do with it.
  $('recover-form').hidden = true;
  $('recover-result').hidden = false;
  $('recover-summary').focus();
});

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  show($('password-error'));
  try {
    reveal(await decryptWithPassword($('recovered').textContent, $('password').value));
    $('recover-summary').textContent = 'Secret recovered and decrypted';
    $('password-form').hidden = true;
    $('password').value = '';
  } catch (error) {
    show($('password-error'), error?.code === 'ERR_WRONG_PASSWORD' ? 'That password is not correct.' : message(error));
  }
});

$('copy-secret').addEventListener('click', (event) => copy($('recovered').textContent, event.currentTarget, 'Secret'));
$('edit-recover').addEventListener('click', () => {
  $('recover-form').hidden = false;
  $('recover-result').hidden = true;
  $('shares-in').focus();
});
$('toggle-secret').addEventListener('click', () => conceal($('toggle-secret').getAttribute('aria-pressed') !== 'true'));
$('clear-recover').addEventListener('click', () => { const held = document.activeElement === $('clear-recover'); clearRecover(); if (held) $('shares-in').focus(); });

// Start clean, even if the browser restored form fields from history.
clearSplit();
clearRecover();
