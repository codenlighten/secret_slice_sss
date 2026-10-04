import { SecretSlicesError, combine, inspect, recover, split, validate } from '../src/index.js';
import { collectShares } from '../src/input.js';
import { decryptWithPassword, isPasswordEncrypted } from '../src/legacy-password.js';
import { generateMnemonic, validateMnemonic } from '../src/mnemonic.js';

const PAD_TO = 64;
const $ = (id) => document.getElementById(id);
const message = (error) => (error instanceof SecretSlicesError ? error.message : `Unexpected error: ${error?.message ?? error}`);

function show(element, text) {
  element.textContent = text ?? '';
  element.hidden = !text;
}

async function copy(text, button) {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Select the text and copy it';
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
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
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

function shareFileName(info, total) {
  return `secretslices-${info.setId.slice(0, 6)}-share-${info.index}-of-${total}.txt`;
}

function clearSplit() {
  currentShares = [];
  $('secret').value = '';
  $('share-list').replaceChildren();
  $('split-result').hidden = true;
  show($('split-error'));
  describeSecret();
}

$('secret').addEventListener('input', describeSecret);
$('generate').addEventListener('click', () => {
  $('secret').value = generateMnemonic(12);
  describeSecret();
});
$('shares').addEventListener('input', () => {
  $('threshold').max = $('shares').value || 255;
});

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
    item.querySelector('.share-text').textContent = share;
    item.querySelector('.copy').addEventListener('click', (e) => copy(share, e.currentTarget));
    item.querySelector('.download').addEventListener('click', () => download(shareFileName(info, shares), `${share}\n`));
    list.append(item);
  });
  $('split-summary').textContent = `${shares} shares created. Any ${threshold} of them recover the secret; ${threshold - 1} or fewer reveal nothing. Checked: they work.`;
  $('split-result').hidden = false;
  $('split-summary').focus();
});

$('download-all').addEventListener('click', () => {
  currentShares.forEach((share, i) => {
    // Browsers block a burst of downloads; space them out.
    setTimeout(() => download(shareFileName(inspect(share), currentShares.length), `${share}\n`), i * 250);
  });
});
$('print').addEventListener('click', () => window.print());
$('clear-split').addEventListener('click', clearSplit);

// -------------------------------------------------------------------- recover

function describeShares() {
  const status = $('share-status');
  status.replaceChildren();
  show($('recover-error'));
  const text = $('shares-in').value;
  if (text.trim() === '') return;

  let items;
  try {
    items = collectShares(text);
  } catch (error) {
    show($('recover-error'), message(error));
    return;
  }
  const sets = new Map();
  const line = (content, className) => {
    const item = document.createElement('li');
    item.textContent = content;
    if (className) item.className = className;
    status.append(item);
  };
  items.forEach((item, i) => {
    const info = validate(item);
    if (!info.valid) {
      line(`Share ${i + 1}: ${info.message}`, 'bad');
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
  for (const [id, set] of sets) {
    const count = set.indexes.size;
    if (set.threshold === undefined) {
      line(`${count} ${count === 1 ? 'share' : 'shares'} in an older SecretSlices format.`, count >= 2 ? 'ok' : '');
    } else if (count >= set.threshold) {
      line(`${count} of the ${set.threshold} shares needed (set ${id.slice(0, 6)}). Ready to recover.`, 'ok');
    } else {
      line(`${count} of the ${set.threshold} shares needed (set ${id.slice(0, 6)}). Add ${set.threshold - count} more.`);
    }
  }
}

function clearRecover() {
  $('shares-in').value = '';
  $('recovered').textContent = '';
  $('password').value = '';
  $('recover-result').hidden = true;
  $('password-form').hidden = true;
  show($('password-error'));
  describeShares();
}

async function addFiles(files) {
  const box = $('shares-in');
  for (const file of files) {
    const text = (await file.text()).trim();
    box.value = box.value.trim() === '' ? text : `${box.value.trim()}\n${text}`;
  }
  describeShares();
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
    return;
  }
  $('recovered').textContent = text;
  $('recover-summary').textContent = result.verified ? 'Secret recovered and verified' : 'Secret recovered';
  show($('recover-warning'), result.verified ? '' :
    'These shares are in an older format that cannot be verified. If the text below looks wrong, a share is incorrect or more shares are needed. Consider splitting the secret again to get verifiable shares.');
  $('password-form').hidden = !isPasswordEncrypted(text);
  $('recover-result').hidden = false;
  $('recover-summary').focus();
});

$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  show($('password-error'));
  try {
    $('recovered').textContent = await decryptWithPassword($('recovered').textContent, $('password').value);
    $('recover-summary').textContent = 'Secret recovered and decrypted';
    $('password-form').hidden = true;
    $('password').value = '';
  } catch (error) {
    show($('password-error'), error?.code === 'ERR_WRONG_PASSWORD' ? 'That password is not correct.' : message(error));
  }
});

$('copy-secret').addEventListener('click', (event) => copy($('recovered').textContent, event.currentTarget));
$('clear-recover').addEventListener('click', clearRecover);

// Start clean, even if the browser restored form fields from history.
clearSplit();
clearRecover();
