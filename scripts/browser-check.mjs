// End-to-end check of web/index.html in a real headless Chrome, driven over
// the DevTools protocol with nothing but Node (>= 22 for the WebSocket client).
// Not part of "npm test" because it needs Chrome installed:
//
//   npm run test:browser            (set CHROME to the browser binary if needed,
//                                    OUT to a directory to keep screenshots)
//
// It splits, recovers, recovers legacy and password-protected shares, and
// confirms that the page's security policy blocks every kind of network
// request and injected script.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const url = process.argv[2] ?? pathToFileURL(join(ROOT, 'web/index.html')).href;
const profile = mkdtempSync(join(tmpdir(), 'ss-chrome-'));
const chrome = spawn(process.env.CHROME ?? 'google-chrome', ['--headless=new', '--remote-debugging-port=9333', `--user-data-dir=${profile}`, '--no-first-run', '--window-size=900,1100', 'about:blank'], { stdio: 'ignore' });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) { await sleep(200); try { target = (await (await fetch('http://127.0.0.1:9333/json')).json()).find((t) => t.type === 'page'); } catch {} }
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0; const pending = new Map(); const events = [];
ws.addEventListener('message', (m) => { const d = JSON.parse(m.data); if (d.id) { pending.get(d.id)(d); pending.delete(d.id); } else events.push(d); });
const send = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
const ev = async (expression) => { const r = await send('Runtime.evaluate', { expression: `(async()=>{${expression}})()`, awaitPromise: true, returnByValue: true }); if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails.exception?.description ?? r.result.exceptionDetails)); return r.result.result.value; };
const shot = async (name) => { if (!process.env.OUT) return; const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }); writeFileSync(join(process.env.OUT, name), Buffer.from(r.result.data, 'base64')); };
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable'); await send('Log.enable');
await send('Page.navigate', { url }); await sleep(800);
const out = {};
const legacy = JSON.parse(readFileSync(`${ROOT}/test/fixtures/legacy.json`, 'utf8'));
const pw = JSON.parse(readFileSync(`${ROOT}/test/fixtures/legacy-password.json`, 'utf8'))[1];
const helpers = `const $=(i)=>document.getElementById(i); const set=(i,v)=>{$(i).value=v;$(i).dispatchEvent(new Event('input',{bubbles:true}));}; const vis=(i)=>!$(i).hidden && $(i).offsetParent!==null;`;
out.initial = await ev(`${helpers} return {title:document.title, splitVisible:vis('panel-split'), recoverVisible:vis('panel-recover'), secret:$('secret').value};`);
await shot('1-initial.png');
out.split = await ev(`${helpers} $('generate').click(); const secret=$('secret').value; const hint=$('secret-hint').textContent; set('shares','5'); set('threshold','3'); $('split-form').requestSubmit(); await new Promise(r=>setTimeout(r,50));
  window.__secret=secret; window.__shares=[...document.querySelectorAll('.share-text')].map(e=>e.textContent);
  return {words:secret.split(' ').length, hint, summary:$('split-summary').textContent, n:window.__shares.length, first:window.__shares[0].slice(0,12), note:document.querySelector('.share-note').textContent, resultVisible:vis('split-result')};`);
await shot('2-split.png');
out.badPhrase = await ev(`${helpers} const s=$('secret').value; set('secret', s.replace(/\\w+$/, 'zoo')===s? s.replace(/\\w+$/, 'abandon'): s.replace(/\\w+$/, 'zoo')); const r=[$('secret-hint').textContent,$('secret-hint').className]; set('secret', window.__secret); return r;`);
out.weak = await ev(`${helpers} set('threshold','1'); $('split-form').noValidate=true; $('split-form').requestSubmit(); await new Promise(r=>setTimeout(r,30)); const e=$('split-error').textContent; set('threshold','3'); return e;`);
out.recoverStatus = await ev(`${helpers} $('tab-recover').click(); set('shares-in', window.__shares.slice(0,2).join('\\n')); const two=[...$('share-status').children].map(e=>e.textContent); $('recover-form').requestSubmit(); await new Promise(r=>setTimeout(r,30)); const err=$('recover-error').textContent;
  set('shares-in', [window.__shares[4],window.__shares[0],window.__shares[2]].join('\\n')); const three=[...$('share-status').children].map(e=>e.textContent); $('recover-form').requestSubmit(); await new Promise(r=>setTimeout(r,30));
  return {two, err, three, ok:$('recovered').textContent===window.__secret, summary:$('recover-summary').textContent, warningHidden:$('recover-warning').hidden, pwHidden:$('password-form').hidden};`);
await shot('3-recover.png');
out.typo = await ev(`${helpers} const s=window.__shares; set('shares-in', [s[0], s[1].slice(0,-3)+'AAA', s[2]].join('\\n')); return [...$('share-status').children].map(e=>e.textContent);`);
const old = legacy.find((f) => f.encoder.startsWith('secrets.js 0.1.8') && f.threshold === 2 && f.text.startsWith('witch'));
out.legacy = await ev(`${helpers} set('shares-in', ${JSON.stringify(JSON.stringify(old.shares.slice(0, 2)))}); const st=[...$('share-status').children].map(e=>e.textContent); $('recover-form').requestSubmit(); await new Promise(r=>setTimeout(r,30)); return {st, ok:$('recovered').textContent===${JSON.stringify(old.text)}, summary:$('recover-summary').textContent, warning:$('recover-warning').textContent.slice(0,60)};`);
await shot('4-legacy.png');
out.password = await ev(`${helpers} set('shares-in', ${JSON.stringify(pw.shares.slice(0, 2).map((s) => JSON.stringify(s)).join('\n'))}); $('recover-form').requestSubmit(); await new Promise(r=>setTimeout(r,30)); const shown=vis('password-form'); const enc=$('recovered').textContent.slice(0,12);
  $('password').value='wrong'; $('password-form').requestSubmit(); await new Promise(r=>setTimeout(r,300)); const wrong=$('password-error').textContent;
  $('password').value=${JSON.stringify(pw.password)}; $('password-form').requestSubmit(); await new Promise(r=>setTimeout(r,300));
  return {shown, enc, wrong, ok:$('recovered').textContent===${JSON.stringify(pw.text)}, summary:$('recover-summary').textContent, formHidden:$('password-form').hidden};`);
out.clear = await ev(`${helpers} $('clear-recover').click(); $('tab-split').click(); $('clear-split').click(); return {a:$('shares-in').value, b:$('recovered').textContent, c:$('secret').value, d:document.querySelectorAll('.share').length};`);
out.network = await ev(`let violations=0; document.addEventListener('securitypolicyviolation',()=>violations++); const r=[]; for (const f of [()=>fetch('https://example.com/'), ()=>new Promise((ok,no)=>{const i=new Image(); i.onload=ok; i.onerror=()=>no(new Error('img blocked')); i.src='https://example.com/x.png';}), ()=>new Promise((ok,no)=>{const s=document.createElement('script'); s.onload=ok; s.onerror=()=>no(new Error('script blocked')); s.src='https://example.com/x.js'; document.head.append(s);}), async()=>{ const e=document.createElement('div'); e.setAttribute('onclick','window.__x=1'); document.body.append(e); e.click(); if(!window.__x) throw new Error('inline handler blocked'); }, async()=>{ (0,eval)('1'); }]) { try { await f(); r.push('ALLOWED'); } catch(e) { r.push(String(e.message).slice(0,40)); } } await new Promise(r=>setTimeout(r,200)); return {r, violations, beacon: navigator.sendBeacon ? (()=>{try{return navigator.sendBeacon('https://example.com/b','x')}catch(e){return 'threw'}})() : 'n/a'};`);
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
await ev(`${helpers} $('generate').click(); $('split-form').requestSubmit(); await new Promise(r=>setTimeout(r,50));`);
out.mobileOverflow = await ev(`return document.documentElement.scrollWidth > window.innerWidth;`);
await shot('5-mobile-dark.png');
out.requests = events.filter((e) => e.method === 'Network.requestWillBeSent').map((e) => e.params.request.url.slice(0, 60));
out.exceptions = events.filter((e) => e.method === 'Runtime.exceptionThrown').map((e) => e.params.exceptionDetails.exception?.description?.slice(0, 200));
out.log = events.filter((e) => e.method === 'Log.entryAdded').map((e) => e.params.entry.text.slice(0, 110));
ws.close(); chrome.kill(); await sleep(300); rmSync(profile, { recursive: true, force: true });

assert.equal(out.initial.splitVisible, true);
assert.equal(out.split.words, 12);
assert.equal(out.split.n, 5);
assert.match(out.split.summary, /Checked: they work/);
assert.equal(out.badPhrase[1], 'hint bad');
assert.match(out.weak, /threshold must be/);
assert.match(out.recoverStatus.err, /needs 3 different shares/);
assert.equal(out.recoverStatus.ok, true);
assert.equal(out.recoverStatus.summary, 'Secret recovered and verified');
assert.match(out.typo[0], /^Share 2: share checksum/);
assert.equal(out.legacy.ok, true);
assert.match(out.legacy.warning, /cannot be verified/);
assert.equal(out.password.shown, true);
assert.equal(out.password.wrong, 'That password is not correct.');
assert.equal(out.password.ok, true);
assert.deepEqual(out.clear, { a: '', b: '', c: '', d: 0 });
assert.ok(out.network.r.every((result) => result !== 'ALLOWED'), `the security policy let something through: ${out.network.r}`);
assert.ok(out.network.violations >= 5);
assert.equal(out.mobileOverflow, false);
assert.deepEqual(out.exceptions, []);
console.log('browser check passed:', url);
