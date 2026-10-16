'use strict';
(() => {
/* ------------------------------------------------------------------ *
 *  My Spends — private expense tracker
 *  Storage : one AES-GCM encrypted file per month in a PRIVATE GitHub repo
 *  Key     : PBKDF2(PIN, random salt, 600k iterations) -> AES-256-GCM
 *  Token   : kept on this phone only, encrypted with the same PIN-derived key
 * ------------------------------------------------------------------ */

const $ = (s, r = document) => r.querySelector(s);
const enc = new TextEncoder(), dec = new TextDecoder();
const LS = { cfg: 'mt_cfg', tok: 'mt_tok', cache: 'mt_cache', tr: 'mt_tr' };
const ITER = 600000, LOCK_MS = 60000;
const PALETTE = ['#f97316','#3b82f6','#ef4444','#a855f7','#10b981','#ec4899','#eab308','#64748b','#14b8a6','#8b5cf6'];
const DEFAULT_CATS = [['Breakfast','🍳','#f2b632'],['Lunch','🍛','#ff7a1a'],['Dinner','🍲','#e11d2a'],['Snacks & Tea','☕','#a86b2d'],
  ['Groceries','🛒','#7fb069'],['Travel','🚌','#4aa3ff'],['Bills','🧾','#9aa0a6'],['Shopping','🛍️','#ff5d8f'],
  ['Health','💊','#2ec4b6'],['Entertainment','🎬','#b388ff'],['Other','📦','#d9cbb8']]
  .map(([n, e, c]) => ({ n, e, c }));
const LEGACY = { Food: { e: '🍽️', c: '#f97316' } };   // old category kept readable
const SV = 3;                                           // settings version (bump when default categories change)
const TRANSPORT = [['Bus','🚌'],['Auto','🛺'],['Train','🚆'],['Metro','🚇'],['Cab','🚕'],['Bike','🏍️'],['Walk','🚶']];
const trIcon = n => (TRANSPORT.find(t => t[0] === n) || [])[1];
const MODES = ['UPI', 'Cash', 'Card', 'Other'];

/* ---------- helpers ---------- */
const pad = n => String(n).padStart(2, '0');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const nowLocal = () => { const d = new Date(); return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; };
const curMonth = () => nowLocal().slice(0, 7);
const shiftMonth = (m, d) => { const [y, mo] = m.split('-').map(Number); const x = new Date(y, mo - 1 + d, 1); return `${x.getFullYear()}-${pad(x.getMonth()+1)}`; };
const monthLabel = m => { const [y, mo] = m.split('-').map(Number); return new Date(y, mo - 1, 1).toLocaleDateString('en-IN', { month: 'long', year: 'numeric' }); };
const daysIn = m => { const [y, mo] = m.split('-').map(Number); return new Date(y, mo, 0).getDate(); };
const f0 = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', maximumFractionDigits: 0 });
const f2 = new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR', minimumFractionDigits: 2, maximumFractionDigits: 2 });
const fmt = n => { const r = Math.round(n * 100) / 100; return Number.isInteger(r) ? f0.format(r) : f2.format(r); };
const sum = a => a.reduce((s, x) => s + x.amt, 0);
const uid = () => crypto.randomUUID();
const b64e = buf => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); };
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const timeOf = ts => new Date(ts).toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit' });
const dayOf = ts => new Date(ts).toLocaleDateString('en-IN', { weekday: 'short', day: 'numeric', month: 'short' });

/* ---------- crypto ---------- */
async function deriveKey(pin, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, iv: b64e(iv), ct: b64e(ct) });
}
async function unseal(key, text) {
  const o = JSON.parse(text);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(o.iv) }, key, b64d(o.ct));
  return JSON.parse(dec.decode(pt));
}

/* ---------- state ---------- */
const newDb = () => ({ months: {}, settings: { cats: DEFAULT_CATS.map(c => ({ ...c })), budget: 0, u: 0, v: SV },
  dirty: [], sdirty: false, ssha: null, last: 0, rev: 0, loans: { items: [], sha: null }, ldirty: false, lrev: 0 });
const S = { cfg: null, key: null, token: null, db: null, syncing: false, hiddenAt: 0,
  ui: { tab: 'home', month: curMonth(), q: '', cat: '', all: false } };
let F = null; // add/edit form state
let L = null; // lending form state

const monthItems = m => (S.db.months[m]?.items || []).filter(x => !x.d);
const allItems = () => Object.values(S.db.months).flatMap(mo => mo.items).filter(x => !x.d);
const findItem = id => { for (const mo of Object.values(S.db.months)) { const x = mo.items.find(i => i.id === id && !i.d); if (x) return x; } return null; };
const catInfo = n => S.db.settings.cats.find(c => c.n === n) || { n, ...(LEGACY[n] || { e: '📦', c: '#64748b' }) };

// one-time upgrade of saved categories: Food -> Breakfast/Lunch/Dinner/Snacks, Travel icon -> bus
function migrateSettings() {
  const s = S.db.settings, v = s.v || 0;
  if (v >= SV) return;
  if (v < 2) {
    const meals = DEFAULT_CATS.slice(0, 4).filter(d => !s.cats.some(c => c.n === d.n)).map(c => ({ ...c }));
    s.cats = [...meals, ...s.cats.filter(c => c.n !== 'Food')];
    const t = s.cats.find(c => c.n === 'Travel'); if (t) t.e = '🚌';
  }
  if (v < 3) {   // red/black/gold theme: recolor the default categories
    const col = Object.fromEntries(DEFAULT_CATS.map(d => [d.n, d.c]));
    s.cats.forEach(c => { if (col[c.n]) c.c = col[c.n]; });
  }
  s.v = SV; touchSettings();
}
// pre-select the meal that fits the time of day
function defaultCat() {
  const h = new Date().getHours(), cats = S.db.settings.cats;
  const want = h >= 5 && h < 11 ? 'Breakfast' : h >= 11 && h < 16 ? 'Lunch' : h >= 16 && h < 19 ? 'Snacks & Tea' : h >= 19 && h < 23 ? 'Dinner' : null;
  return cats.find(c => c.n === want)?.n || cats[0]?.n || 'Other';
}
function lastTr() { try { return localStorage.getItem(LS.tr) || 'Bus'; } catch { return 'Bus'; } }

function upsert(it) {
  const m = it.ts.slice(0, 7);
  const mo = S.db.months[m] || (S.db.months[m] = { items: [], sha: null });
  const i = mo.items.findIndex(x => x.id === it.id);
  if (i >= 0) mo.items[i] = it; else mo.items.push(it);
  if (!S.db.dirty.includes(m)) S.db.dirty.push(m);
  S.db.rev++;
}
const tombstone = old => upsert({ id: old.id, ts: old.ts, d: 1, u: Date.now() });

/* ---------- persistence (encrypted local cache) ---------- */
let pt;
function persist(now) {
  clearTimeout(pt);
  const run = async () => {
    if (!S.key || !S.db) return;
    try { localStorage.setItem(LS.cache, await seal(S.key, S.db)); } catch (e) { console.warn('cache save failed', e); }
  };
  if (now) return run();
  pt = setTimeout(run, 300);
}

/* ---------- GitHub API ---------- */
class ApiErr extends Error { constructor(status, msg) { super(msg || 'GitHub ' + status); this.status = status; } }
async function gh(method, path, body) {
  const res = await fetch(`https://api.github.com/repos/${S.cfg.repo}${path}`, {
    method, cache: 'no-store',
    headers: { Authorization: 'Bearer ' + S.token, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  let json = null; try { json = await res.json(); } catch {}
  return { status: res.status, ok: res.ok, json };
}
async function ghGet(path) {
  const r = await gh('GET', '/contents/' + path);
  if (r.status === 404) return null;
  if (!r.ok) throw new ApiErr(r.status);
  return { sha: r.json.sha, text: atob(r.json.content.replace(/\s/g, '')) };
}
async function ghList() {
  const r = await gh('GET', '/contents/data');
  if (r.status === 404) return [];
  if (!r.ok) throw new ApiErr(r.status);
  return Array.isArray(r.json) ? r.json : [];
}
async function ghPut(path, text, sha) {
  const r = await gh('PUT', '/contents/' + path, { message: 'update', content: btoa(text), ...(sha ? { sha } : {}) });
  return { ok: r.ok, status: r.status, sha: r.json?.content?.sha };
}

/* ---------- sync (merge by item id, newest edit wins; deletes are tombstones) ---------- */
function mergeItems(a, b) {
  const m = new Map();
  for (const x of [...b, ...a]) { const y = m.get(x.id); if (!y || (x.u || 0) >= (y.u || 0)) m.set(x.id, x); }
  return [...m.values()].sort((p, q) => p.ts.localeCompare(q.ts) || p.id.localeCompare(q.id));
}
const sameSet = (a, b) => { if (a.length !== b.length) return false; const m = new Map(b.map(x => [x.id, x.u])); return a.every(x => m.get(x.id) === x.u); };

async function syncMonth(m) {
  let changed = false;
  for (let t = 0; t < 3; t++) {
    const r = await ghGet(`data/${m}.enc`);
    let remote = [], sha = null;
    if (r) { sha = r.sha; remote = (await unseal(S.key, r.text)).items || []; }
    const local = S.db.months[m]?.items || [];
    const before = JSON.stringify(local);
    const merged = mergeItems(local, remote);
    if (JSON.stringify(merged) !== before) changed = true;
    S.db.months[m] = { items: merged, sha };
    const rev = S.db.rev;
    if (!merged.length || (r && sameSet(merged, remote))) { S.db.dirty = S.db.dirty.filter(x => x !== m); return changed; }
    const res = await ghPut(`data/${m}.enc`, await seal(S.key, { v: 1, items: merged }), sha);
    if (res.ok) {
      S.db.months[m].sha = res.sha;
      if (S.db.rev === rev) S.db.dirty = S.db.dirty.filter(x => x !== m);
      return changed;
    }
    if (res.status !== 409 && res.status !== 422) throw new ApiErr(res.status);
  }
  throw new ApiErr(409, 'Too many conflicts');
}

async function syncSettings() {
  for (let t = 0; t < 3; t++) {
    const r = await ghGet('data/settings.enc');
    let remote = null, sha = null;
    if (r) { sha = r.sha; remote = await unseal(S.key, r.text); }
    const local = S.db.settings;
    if (remote && (remote.u || 0) > (local.u || 0)) {
      S.db.settings = { cats: remote.cats, budget: remote.budget, u: remote.u, v: remote.v };
      S.db.sdirty = false; S.db.ssha = sha; return true;
    }
    S.db.ssha = sha;
    if (!S.db.sdirty) return false;
    const res = await ghPut('data/settings.enc', await seal(S.key, { v: 1, ...local }), sha);
    if (res.ok) { S.db.ssha = res.sha; S.db.sdirty = false; return false; }
    if (res.status !== 409 && res.status !== 422) throw new ApiErr(res.status);
  }
  throw new ApiErr(409, 'Too many conflicts');
}

/* ---------- lending (money lent to friends) ---------- */
// Every entry is one record: { id, k:'lend'|'repay', who, amt, ts, note, u, d? }.
// A friend's balance = sum(lend) - sum(repay), so two devices can never overwrite each other's repayments.
const pkey = n => String(n).trim().toLowerCase().replace(/\s+/g, ' ');
const loanItems = () => S.db.loans.items.filter(x => !x.d);
const findLoan = id => S.db.loans.items.find(x => x.id === id && !x.d) || null;
function upsertLoan(it) {
  const a = S.db.loans.items, i = a.findIndex(x => x.id === it.id);
  if (i >= 0) a[i] = it; else a.push(it);
  S.db.ldirty = true; S.db.lrev++;
}
const daysAgo = ts => Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 864e5));
const shortDate = ts => new Date(ts).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
const longDate = ts => new Date(ts).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' }) + ', ' + timeOf(ts);

function people() {
  const m = new Map();
  for (const x of loanItems()) {
    const k = pkey(x.who);
    let p = m.get(k);
    if (!p) m.set(k, p = { key: k, name: x.who.trim(), lent: 0, rep: 0, items: [], first: x.ts, last: x.ts });
    p.items.push(x);
    if (x.k === 'repay') p.rep += x.amt; else p.lent += x.amt;
    if (x.ts < p.first) p.first = x.ts;
    if (x.ts > p.last) p.last = x.ts;
  }
  const out = [...m.values()];
  out.forEach(p => {
    p.lent = Math.round(p.lent * 100) / 100; p.rep = Math.round(p.rep * 100) / 100;
    p.bal = Math.round((p.lent - p.rep) * 100) / 100;
    p.items.sort((a, b) => b.ts.localeCompare(a.ts));
  });
  return out;
}

function lentCardHtml() {
  const ps = people().filter(p => p.bal > 0.004);
  if (!ps.length) return '';
  const t = ps.reduce((s, p) => s + p.bal, 0);
  return `<button class="card wide lentcard" data-a="tab" data-v="lent"><span><small>Lent out · to get back</small><b>${fmt(t)}</b></span><span class="mut">${ps.length} ${ps.length === 1 ? 'person' : 'people'} ›</span></button>`;
}

function personRow(p) {
  const pending = p.bal > 0.004, adv = p.bal < -0.004;
  const pct = p.lent ? Math.min(100, p.rep / p.lent * 100) : 0, age = daysAgo(p.first);
  const meta = pending
    ? 'Lent ' + fmt(p.lent) + ' · Repaid ' + fmt(p.rep) + ' · since ' + shortDate(p.first) + (age >= 30 ? ' · ' + age + ' days' : '')
    : 'Fully repaid · ' + shortDate(p.last);
  return `<button class="person" data-a="person" data-v="${esc(p.key)}">
    <span class="av">${esc(p.name.charAt(0).toUpperCase())}</span>
    <span class="mid"><b>${esc(p.name)}</b><small>${esc(meta)}</small><span class="pbar"><b style="width:${pct}%"></b></span></span>
    <span class="due ${pending ? '' : 'ok'}"><b>${pending ? fmt(p.bal) : adv ? fmt(-p.bal) : '✓'}</b><small>${pending ? 'to get back' : adv ? 'extra paid' : 'settled'}</small></span></button>`;
}

function renderLent() {
  const ps = people();
  const owing = ps.filter(p => p.bal > 0.004).sort((a, b) => b.bal - a.bal);
  const done = ps.filter(p => p.bal <= 0.004).sort((a, b) => b.last.localeCompare(a.last));
  const all = loanItems();
  const lent = sum(all.filter(x => x.k !== 'repay')), got = sum(all.filter(x => x.k === 'repay'));
  const toGet = owing.reduce((s, p) => s + p.bal, 0);
  const pct = lent ? Math.min(100, got / lent * 100) : 0;
  if (!ps.length) {
    $('#view').innerHTML = `<div class="card hero"><div class="lbl">To get back</div><div class="big">${fmt(0)}</div></div>
      <div class="card empty">Nobody owes you anything yet.<br>Tap <b>+</b> when you lend money to a friend.</div>`;
    return;
  }
  let h = `<div class="card hero"><div class="lbl">To get back</div><div class="big">${fmt(toGet)}</div>
    <div class="sub"><span>${owing.length} ${owing.length === 1 ? 'person' : 'people'} pending</span><span>Lent in total ${fmt(lent)}</span></div>
    <div class="bud"><div class="bar"><b style="width:${pct}%"></b></div>
    <div class="sub"><span>Received back ${fmt(got)}</span><span>${Math.round(pct)}%</span></div></div></div>`;
  h += owing.length
    ? `<div class="card wide"><h3>Pending (${owing.length})</h3>${owing.map(personRow).join('')}</div>`
    : `<div class="card empty wide">🎉 Everyone has paid you back.</div>`;
  if (done.length) {
    const open = !!S.ui.settled;
    h += `<div class="card wide"><button class="secthead rowbtn" data-a="show-settled"><h3>Settled (${done.length})</h3><span class="mut">${open ? 'Hide' : 'Show'}</span></button>${open ? done.map(personRow).join('') : ''}</div>`;
  }
  $('#view').innerHTML = h;
}

function entryRow(x) {
  const rep = x.k === 'repay';
  return `<button class="item" data-a="loan-edit" data-v="${esc(x.id)}">
    <span class="ico" style="background:${rep ? '#f2b63226' : '#e11d2a2e'};color:${rep ? 'var(--gold)' : '#ff6b6b'}">${rep ? '↙' : '↗'}</span>
    <span class="mid"><b>${rep ? 'Repaid' : 'Lent'}${x.note ? ' · ' + esc(x.note) : ''}</b><small>${esc(longDate(x.ts))}</small></span>
    <span class="amt ${rep ? 'in' : 'out'}">${rep ? '−' : '+'}${fmt(x.amt)}</span></button>`;
}

function openPerson(key) {
  const p = people().find(x => x.key === key);
  if (!p) { closeSheet(); return; }
  F = null; L = null;
  const pending = p.bal > 0.004, adv = p.bal < -0.004;
  const pct = p.lent ? Math.min(100, p.rep / p.lent * 100) : 0;
  $('#panel').innerHTML = `<div class="grab"></div>
    <div class="sh-head"><h2>${esc(p.name)}</h2><button class="x" data-a="close" aria-label="Close">✕</button></div>
    <div class="ph"><div class="lbl">${pending ? 'Owes you' : adv ? 'Paid extra' : 'All settled 🎉'}</div>
      <div class="big">${fmt(Math.abs(p.bal))}</div>
      <div class="pbar big"><b style="width:${pct}%"></b></div>
      <div class="sub mut"><span>Lent ${fmt(p.lent)}</span><span>Repaid ${fmt(p.rep)}</span></div></div>
    <div class="acts"><button class="btn" data-a="lend-more" data-v="${esc(p.key)}">Lend more</button>
      <button class="btn gold" data-a="got-back" data-v="${esc(p.key)}">Got repayment</button></div>
    ${pending ? `<button class="btn ghost" data-a="settle" data-v="${esc(p.key)}">Mark fully repaid (${fmt(p.bal)})</button>
      <button class="btn ghost" data-a="remind" data-v="${esc(p.key)}">Remind on WhatsApp</button>` : ''}
    <div class="fl">History · tap an entry to edit</div>
    <div class="card" style="padding:4px 14px">${p.items.map(entryRow).join('')}</div>`;
  $('#sheet').classList.remove('hidden');
}

const loanTitle = () => L.id ? 'Edit entry' : L.k === 'repay' ? 'Repayment received' : 'Lend money';

function openLoanSheet(o = {}) {
  const it = o.id ? findLoan(o.id) : null;
  F = null;
  L = it ? { ...it, back: !!o.back } : { id: null, k: o.kind || 'lend', who: o.who || '', amt: '', ts: nowLocal(), note: '', back: !!o.back };
  const names = people().map(p => p.name);
  $('#panel').innerHTML = `<div class="grab"></div>
    <div class="sh-head"><h2 id="l-title">${loanTitle()}</h2><button class="x" data-a="close" aria-label="Close">✕</button></div>
    <div class="seg"><button class="${L.k === 'lend' ? 'on' : ''}" data-a="lk" data-v="lend">I lent</button><button class="${L.k === 'repay' ? 'on' : ''}" data-a="lk" data-v="repay" data-r="1">They repaid</button></div>
    <div class="fl">Friend</div>
    <input id="l-who" maxlength="40" placeholder="Name, e.g. Abbas" autocomplete="off" value="${esc(L.who)}">
    ${names.length ? `<div class="chips" style="margin-top:8px">${names.map(n => `<button class="chip" data-a="lpick" data-v="${esc(n)}">${esc(n)}</button>`).join('')}</div>` : ''}
    <div class="fl">Amount</div>
    <div class="amtbox" style="margin-top:0"><span>₹</span><input id="l-amt" inputmode="decimal" placeholder="0" autocomplete="off" value="${L.amt}"></div>
    <div class="chips"><button id="l-full" class="chip hidden" data-a="lfull"></button></div>
    <div class="fl">Date & time</div><input id="l-ts" type="datetime-local" value="${esc(L.ts)}">
    <div class="fl">Note (optional)</div><input id="l-note" maxlength="80" placeholder="e.g. for movie tickets" autocomplete="off" value="${esc(L.note || '')}">
    <button class="btn big" data-a="loan-save">Save</button>
    ${it ? '<button class="btn ghost danger" data-a="loan-del">Delete entry</button>' : ''}`;
  $('#sheet').classList.remove('hidden');
  refreshFull();
  if (!it) setTimeout(() => { const e = $(L && L.who ? '#l-amt' : '#l-who'); if (e) e.focus(); }, 120);
}

// "Full ₹X" shortcut when recording a repayment for someone who owes money
function refreshFull() {
  const b = $('#l-full'); if (!b || !L) return;
  const p = people().find(x => x.key === pkey($('#l-who').value || ''));
  if (!L.id && L.k === 'repay' && p && p.bal > 0.004) { b.textContent = 'Full ' + fmt(p.bal); b.dataset.v = String(p.bal); b.classList.remove('hidden'); }
  else b.classList.add('hidden');
}

function saveLoan() {
  const who = $('#l-who').value.trim();
  const amt = Math.round(parseFloat($('#l-amt').value) * 100) / 100;
  const ts = $('#l-ts').value;
  if (!who) return toast("Enter your friend's name");
  if (!(amt > 0) || amt > 1e9) return toast('Enter an amount');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(ts)) return toast('Pick a date and time');
  const ex = people().find(p => p.key === pkey(who));
  if (L.k === 'repay' && ex) {
    const other = ex.items.filter(x => x.id !== L.id);
    const pend = sum(other.filter(x => x.k !== 'repay')) - sum(other.filter(x => x.k === 'repay'));
    if (amt > pend + 0.004 && !confirm(ex.name + ' only owes ' + fmt(Math.max(pend, 0)) + '. Save this repayment anyway?')) return;
  }
  const name = ex ? ex.name : who;
  const item = { id: L.id || uid(), k: L.k, who: name, amt, ts: ts.slice(0, 16), note: $('#l-note').value.trim(), u: Date.now() };
  const back = L.back;
  upsertLoan(item);
  closeSheet(); render(); persist(); scheduleSync();
  toast((item.k === 'repay' ? 'Received ' : 'Lent ') + fmt(amt) + ' · ' + name);
  if (back) openPerson(pkey(name));
}

function deleteLoan() {
  if (!L || !L.id || !confirm('Delete this entry?')) return;
  const old = findLoan(L.id), back = L.back;
  if (old) upsertLoan({ id: old.id, k: old.k, who: old.who, ts: old.ts, d: 1, u: Date.now() });
  closeSheet(); render(); persist(); scheduleSync(); toast('Deleted');
  if (back && old) openPerson(pkey(old.who));
}

function settleLoan(key) {
  const p = people().find(x => x.key === key);
  if (!p || p.bal <= 0.004) return;
  if (!confirm('Mark ' + fmt(p.bal) + ' from ' + p.name + ' as fully repaid?')) return;
  upsertLoan({ id: uid(), k: 'repay', who: p.name, amt: p.bal, ts: nowLocal(), note: 'Settled', u: Date.now() });
  render(); persist(); scheduleSync(); openPerson(key); toast('Marked as settled');
}

function remindLoan(key) {
  const p = people().find(x => x.key === key);
  if (!p || p.bal <= 0.004) return;
  const text = 'Hi ' + p.name + ', a gentle reminder: ' + fmt(p.bal) + ' is pending that I lent you. Please return it when you can. Thanks!';
  window.open('https://wa.me/?text=' + encodeURIComponent(text), '_blank', 'noopener');
}

function exportLoans() {
  const cell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const rows = loanItems().sort((a, b) => a.ts.localeCompare(b.ts))
    .map(x => [x.ts.slice(0, 10), x.ts.slice(11, 16), x.k === 'repay' ? 'Repaid' : 'Lent', x.who, x.amt, x.note].map(cell).join(','));
  const blob = new Blob(['﻿' + ['Date,Time,Type,Friend,Amount,Note', ...rows].join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'lending-' + nowLocal().slice(0, 10) + '.csv';
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  toast('Exported ' + rows.length + ' entries');
}

async function syncLoans() {
  let changed = false;
  for (let t = 0; t < 3; t++) {
    const r = await ghGet('data/loans.enc');
    let remote = [], sha = null;
    if (r) { sha = r.sha; remote = (await unseal(S.key, r.text)).items || []; }
    const local = S.db.loans.items, before = JSON.stringify(local);
    const merged = mergeItems(local, remote);
    if (JSON.stringify(merged) !== before) changed = true;
    S.db.loans = { items: merged, sha };
    const rev = S.db.lrev;
    if (!merged.length || (r && sameSet(merged, remote))) { S.db.ldirty = false; return changed; }
    const res = await ghPut('data/loans.enc', await seal(S.key, { v: 1, items: merged }), sha);
    if (res.ok) {
      S.db.loans.sha = res.sha;
      if (S.db.lrev === rev) S.db.ldirty = false;
      return changed;
    }
    if (res.status !== 409 && res.status !== 422) throw new ApiErr(res.status);
  }
  throw new ApiErr(409, 'Too many conflicts');
}

function setSync(cls, text) { const b = $('#sync'); b.className = 'sync ' + cls; $('span', b).textContent = text; }
let st;
const scheduleSync = () => { clearTimeout(st); st = setTimeout(sync, 1200); };

async function sync() {
  if (!S.key || S.syncing) return;
  if (!navigator.onLine) { setSync('off', 'Offline'); return; }
  S.syncing = true; setSync('busy', 'Syncing…');
  let ok = false, changed = false;
  try {
    const list = await ghList();
    const rem = {}; let ssha = null, lsha = null;
    for (const f of list) {
      const mm = /^(\d{4}-\d{2})\.enc$/.exec(f.name);
      if (mm) rem[mm[1]] = f.sha; else if (f.name === 'settings.enc') ssha = f.sha; else if (f.name === 'loans.enc') lsha = f.sha;
    }
    const months = new Set(S.db.dirty);
    for (const m in rem) if (!S.db.months[m] || S.db.months[m].sha !== rem[m]) months.add(m);
    for (const m of months) { if (!S.key) return; if (await syncMonth(m)) changed = true; }
    if (S.db.sdirty || ssha !== S.db.ssha) { if (await syncSettings()) changed = true; }
    if (S.db.ldirty || lsha !== S.db.loans.sha) { if (await syncLoans()) changed = true; }
    S.db.last = Date.now(); ok = true;
    persist(); setSync('ok', 'Synced');
    if (changed) render();
  } catch (e) {
    if (!S.key) return;
    if (e.status === 401 || e.status === 403) { setSync('err', 'Token problem'); toast('GitHub rejected the token. Update it in Settings.'); }
    else if (e instanceof TypeError) setSync('off', 'Offline');
    else { setSync('err', 'Sync failed'); console.error(e); }
  } finally {
    S.syncing = false;
    if (ok && S.db && S.db.dirty.length) scheduleSync();
  }
}

/* ---------- screens: setup / unlock / lock ---------- */
function show(id) { for (const s of ['setup', 'lock', 'main']) $('#' + s).classList.toggle('hidden', s !== id); }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2400); }

async function setup() {
  const err = $('#s-err'), btn = $('#s-go'); err.textContent = '';
  const repo = $('#s-repo').value.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
  const token = $('#s-token').value.trim(), pin = $('#s-pin').value, pin2 = $('#s-pin2').value;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) return err.textContent = 'Repo should look like username/money-data';
  if (token.length < 20) return err.textContent = 'Paste your GitHub token.';
  if (pin.length < 6) return err.textContent = 'PIN must be at least 6 characters.';
  if (pin !== pin2) return err.textContent = 'PINs do not match.';
  btn.disabled = true; btn.textContent = 'Checking…';
  S.cfg = { repo }; S.token = token;
  try {
    const r = await gh('GET', '');
    if (r.status === 401) throw new Error('GitHub rejected the token.');
    if (r.status === 404) throw new Error("Can't see that repo. Check the name and that the token has access to it.");
    if (!r.ok) throw new Error('GitHub error ' + r.status);
    if (!r.json.private) throw new Error('That repo is PUBLIC. Make it private first. Your data must not sit in a public repo.');
    if (r.json.permissions && r.json.permissions.push === false) throw new Error('Token is read-only. It needs Contents: Read and write.');

    let salt, iter, key;
    const meta = await ghGet('data/meta.json');
    if (meta) {
      const m = JSON.parse(meta.text); salt = b64d(m.salt); iter = m.iter;
      key = await deriveKey(pin, salt, iter);
      const chk = await ghGet('data/check.enc');
      if (chk) { try { await unseal(key, chk.text); } catch { throw new Error('Wrong PIN for the data already in this repo.'); } }
      else { const p = await ghPut('data/check.enc', await seal(key, { ok: 1 })); if (!p.ok) throw new Error('Could not write to the repo (' + p.status + ').'); }
    } else {
      salt = crypto.getRandomValues(new Uint8Array(16)); iter = ITER;
      key = await deriveKey(pin, salt, iter);
      const p1 = await ghPut('data/meta.json', JSON.stringify({ v: 1, salt: b64e(salt), iter }));
      if (!p1.ok) throw new Error('Could not write to the repo (' + p1.status + '). Add a README to the repo first and check the token has Contents: Read and write.');
      const p2 = await ghPut('data/check.enc', await seal(key, { ok: 1 }));
      if (!p2.ok) throw new Error('Could not write to the repo (' + p2.status + ').');
    }
    S.cfg = { repo, salt: b64e(salt), iter };
    localStorage.setItem(LS.cfg, JSON.stringify(S.cfg));
    localStorage.setItem(LS.tok, await seal(key, { t: token }));
    localStorage.removeItem(LS.cache);
    S.key = key; S.db = newDb();
    for (const id of ['s-repo', 's-token', 's-pin', 's-pin2']) $('#' + id).value = '';
    enter();
  } catch (e) {
    S.cfg = null; S.token = null; S.key = null;
    err.textContent = e instanceof TypeError ? 'No internet connection.' : e.message;
  } finally { btn.disabled = false; btn.textContent = 'Continue'; }
}

async function unlock() {
  const pin = $('#pin').value, err = $('#l-err'), btn = $('#l-go');
  if (!pin) return;
  err.textContent = ''; btn.disabled = true; btn.textContent = 'Unlocking…';
  try {
    const key = await deriveKey(pin, b64d(S.cfg.salt), S.cfg.iter);
    const { t } = await unseal(key, localStorage.getItem(LS.tok));
    S.key = key; S.token = t;
  } catch {
    btn.disabled = false; btn.textContent = 'Unlock';
    err.textContent = 'Wrong PIN'; $('#pin').value = '';
    const p = $('#pin'); p.classList.remove('shake'); void p.offsetWidth; p.classList.add('shake');
    return;
  }
  btn.disabled = false; btn.textContent = 'Unlock'; $('#pin').value = '';
  let db = null;
  try { const c = localStorage.getItem(LS.cache); if (c) db = await unseal(S.key, c); } catch {}
  S.db = Object.assign(newDb(), db || {});
  enter();
}

function enter() {
  S.ui = { tab: 'home', month: curMonth(), q: '', cat: '', all: false };
  show('main'); setSync('off', navigator.onLine ? 'Ready' : 'Offline'); render(); sync();
}

async function lock() {
  if (!S.key) return;
  try { await persist(true); } catch {}
  S.key = S.token = S.db = null; F = null;
  $('#view').innerHTML = ''; $('#panel').innerHTML = ''; $('#sheet').classList.add('hidden');
  show('lock'); $('#pin').focus();
}

/* ---------- rendering ---------- */
function render() {
  migrateSettings();
  $('#view').dataset.tab = S.ui.tab;
  renderHeader();
  document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.v === S.ui.tab));
  ({ home: renderHome, history: renderHistory, lent: renderLent, settings: renderSettings })[S.ui.tab]();
}

function renderHeader() {
  const l = $('#hdr-left'), m = S.ui.month;
  if (S.ui.tab === 'lent') l.innerHTML = '<h1>Money lent</h1>';
  else if (S.ui.tab === 'settings') l.innerHTML = '<h1>Settings</h1>';
  else if (S.ui.tab === 'history' && S.ui.all) l.innerHTML = '<h1>All expenses</h1>';
  else l.innerHTML = `<button class="nav" data-a="mprev" aria-label="Previous month">‹</button>
    <button class="mlabel" data-a="mnow">${esc(monthLabel(m))}</button>
    <button class="nav" data-a="mnext" aria-label="Next month" ${m >= curMonth() ? 'disabled' : ''}>›</button>`;
}

function rowHtml(x) {
  const c = catInfo(x.cat);
  const ti = x.cat === 'Travel' && x.tr ? trIcon(x.tr) : null;
  return `<button class="item" data-a="edit" data-v="${esc(x.id)}">
    <span class="ico" style="background:${esc(c.c)}26">${esc(ti || c.e)}</span>
    <span class="mid"><b>${esc(x.note || x.tr || x.cat)}</b><small>${esc(x.tr ? x.cat + ' · ' + x.tr : x.cat)} · ${timeOf(x.ts)}${x.m ? ' · ' + esc(x.m) : ''}</small></span>
    <span class="amt">${fmt(x.amt)}</span></button>`;
}

function renderHome() {
  const m = S.ui.month, items = monthItems(m), total = sum(items);
  const prev = sum(monthItems(shiftMonth(m, -1)));
  const days = daysIn(m), isCur = m === curMonth(), today = new Date().getDate();
  const elapsed = isCur ? today : days, bud = S.db.settings.budget || 0;

  let hero = `<div class="card hero"><div class="lbl">Spent in ${esc(monthLabel(m))}</div>
    <div class="big">${fmt(total)}</div>
    <div class="sub"><span>${items.length} transaction${items.length === 1 ? '' : 's'}</span><span>Avg/day ${fmt(total / elapsed)}</span></div>
    ${prev ? `<div class="sub mut"><span>Last month ${fmt(prev)}</span></div>` : ''}`;
  if (bud > 0) {
    const pct = Math.min(100, total / bud * 100), left = bud - total;
    hero += `<div class="bud ${total > bud ? 'over' : pct > 80 ? 'warn' : ''}"><div class="bar"><b style="width:${pct}%"></b></div>
      <div class="sub"><span>Budget ${fmt(bud)}</span><span>${left >= 0 ? fmt(left) + ' left' : fmt(-left) + ' over'}</span></div></div>`;
  }
  hero += '</div>' + lentCardHtml();

  if (!items.length) {
    $('#view').innerHTML = hero + '<div class="card empty">No expenses this month.<br>Tap <b>+</b> to add one.</div>';
    return;
  }

  const by = {}; items.forEach(x => by[x.cat] = (by[x.cat] || 0) + x.amt);
  const cats = Object.entries(by).sort((a, b) => b[1] - a[1]);
  let off = 25, segs = '';
  cats.forEach(([n, v]) => { const p = v / total * 100; segs += `<circle cx="21" cy="21" r="15.915" fill="none" stroke="${esc(catInfo(n).c)}" stroke-width="6" stroke-dasharray="${p} ${100 - p}" stroke-dashoffset="${off}"/>`; off -= p; });
  const legend = cats.map(([n, v]) => { const c = catInfo(n); return `<div class="lg"><span class="dot" style="background:${esc(c.c)}"></span><span class="nm">${esc(c.e)} ${esc(n)}</span><b>${fmt(v)}</b><em>${Math.round(v / total * 100)}%</em></div>`; }).join('');

  const perDay = Array(days).fill(0); items.forEach(x => perDay[+x.ts.slice(8, 10) - 1] += x.amt);
  const mx = Math.max(...perDay, 1), hi = perDay.indexOf(Math.max(...perDay));
  const bars = perDay.map((v, i) => { const h = v ? Math.max(3, v / mx * 66) : 0; return `<rect class="bar${isCur && i + 1 === today ? ' cur' : ''}" x="${i * 10 + 1}" y="${70 - h}" width="8" height="${h}" rx="2"/>`; }).join('');
  const ticks = [1, 8, 15, 22, days].filter((d, i, a) => a.indexOf(d) === i).map(d => `<text class="axis" x="${(d - 1) * 10 + 5}" y="84" text-anchor="middle">${d}</text>`).join('');
  const recent = items.slice().sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 5).map(rowHtml).join('');

  $('#view').innerHTML = hero + `
    <div class="card"><h3>By area</h3><div class="donutwrap">
      <svg class="donut" viewBox="0 0 42 42"><circle cx="21" cy="21" r="15.915" fill="none" stroke="var(--chip)" stroke-width="6"/>${segs}<text class="dtxt" x="21" y="22.5">${cats.length} area${cats.length === 1 ? '' : 's'}</text></svg>
      <div class="legend">${legend}</div></div></div>
    <div class="card"><h3>Daily spending</h3>
      <svg class="bars" viewBox="0 0 ${days * 10} 90"><line class="base" x1="0" x2="${days * 10}" y1="70" y2="70"/>${bars}${ticks}</svg>
      <div class="sub mut"><span>Highest: ${fmt(perDay[hi])} on ${hi + 1} ${esc(new Date(m + '-01').toLocaleDateString('en-IN', { month: 'short' }))}</span></div></div>
    <div class="card wide"><div class="secthead"><h3>Recent</h3><button class="link" data-a="tab" data-v="history">See all</button></div>${recent}</div>`;
}

function histItems() {
  let it = S.ui.all ? allItems() : monthItems(S.ui.month);
  if (S.ui.cat) it = it.filter(x => x.cat === S.ui.cat);
  const q = S.ui.q.trim().toLowerCase();
  if (q) it = it.filter(x => (x.note || '').toLowerCase().includes(q) || x.cat.toLowerCase().includes(q) || String(x.amt).includes(q));
  return it.sort((a, b) => b.ts.localeCompare(a.ts));
}
function updateHistList() {
  const it = histItems(), box = $('#hlist');
  if (!it.length) { box.innerHTML = '<div class="empty">Nothing here.</div>'; return; }
  const groups = {}; it.forEach(x => (groups[x.ts.slice(0, 10)] ||= []).push(x));
  box.innerHTML = `<div class="card">` + Object.keys(groups).sort().reverse().map(d =>
    `<div class="dayhead"><span>${esc(dayOf(d + 'T00:00'))}</span><span>${fmt(sum(groups[d]))}</span></div>` + groups[d].map(rowHtml).join('')).join('') + `</div>`
    + `<div class="sub mut"><span>${it.length} item${it.length === 1 ? '' : 's'}</span><span>Total ${fmt(sum(it))}</span></div>`;
}
function renderHistory() {
  const base = S.ui.all ? allItems() : monthItems(S.ui.month);
  const used = [...new Set(base.map(x => x.cat))];
  if (S.ui.cat && !used.includes(S.ui.cat)) S.ui.cat = '';
  $('#view').innerHTML = `<div class="searchrow"><input id="q" type="search" placeholder="Search purpose, area, amount" value="${esc(S.ui.q)}">
    <button class="chip ${S.ui.all ? 'on' : ''}" data-a="toggle-all">All months</button></div>
    <div class="chips scroll"><button class="chip ${!S.ui.cat ? 'on' : ''}" data-a="fcat" data-v="">All</button>
    ${used.map(n => `<button class="chip ${S.ui.cat === n ? 'on' : ''}" data-a="fcat" data-v="${esc(n)}">${esc(catInfo(n).e)} ${esc(n)}</button>`).join('')}</div>
    <div id="hlist"></div>`;
  updateHistList();
}

function renderSettings() {
  const st = S.db.settings;
  $('#view').innerHTML = `
    <div class="card"><h3>Monthly budget</h3><div class="row"><span class="pre">₹</span>
      <input id="budget" inputmode="decimal" value="${st.budget || ''}" placeholder="0 = no budget"></div></div>
    <div class="card"><h3>Categories</h3>
      ${st.cats.map(c => `<div class="catrow"><span class="dot" style="background:${esc(c.c)}"></span><span>${esc(c.e)} ${esc(c.n)}</span><button class="x" data-a="del-cat" data-v="${esc(c.n)}" aria-label="Remove">✕</button></div>`).join('')}
      <div class="row addcat"><input id="nc-e" class="emo" maxlength="4" placeholder="🙂"><input id="nc-n" maxlength="24" placeholder="New category"><button class="btn sm" data-a="add-cat">Add</button></div></div>
    <div class="card"><h3>Data & security</h3><div class="stack">
      <button class="btn ghost" style="margin:0" data-a="sync">Sync now</button>
      <button class="btn ghost" style="margin:0" data-a="export">Export expenses as CSV</button>
      <button class="btn ghost" style="margin:0" data-a="export-loans">Export lending as CSV</button>
      <button class="btn ghost" style="margin:0" data-a="token">Update GitHub token</button>
      <button class="btn ghost" style="margin:0" data-a="lock-now">Lock now</button>
      <button class="btn ghost danger" style="margin:0" data-a="forget">Forget this device</button></div>
      <p class="tiny" style="margin-top:12px">Auto-locks after 1 minute in the background. Repo: ${esc(S.cfg.repo)}</p></div>`;
}

/* ---------- add / edit sheet ---------- */
function openSheet(id) {
  const it = id ? findItem(id) : null;
  F = it ? { ...it } : { id: null, amt: '', cat: defaultCat(), note: '', ts: nowLocal(), m: 'UPI', tr: lastTr() };
  const cats = S.db.settings.cats.slice();
  if (!cats.find(c => c.n === F.cat)) cats.push(catInfo(F.cat));
  $('#panel').innerHTML = `<div class="grab"></div>
    <div class="sh-head"><h2>${it ? 'Edit expense' : 'Add expense'}</h2><button class="x" data-a="close" aria-label="Close">✕</button></div>
    <div class="amtbox"><span>₹</span><input id="f-amt" inputmode="decimal" placeholder="0" autocomplete="off" value="${F.amt}"></div>
    <div class="fl">Area</div>
    <div class="chips" id="f-cats">${cats.map(c => `<button class="chip ${c.n === F.cat ? 'on' : ''}" data-a="pick-cat" data-v="${esc(c.n)}">${esc(c.e)} ${esc(c.n)}</button>`).join('')}</div>
    <div id="f-trw" class="${F.cat === 'Travel' ? '' : 'hidden'}"><div class="fl">Transport</div>
      <div class="chips" id="f-tr">${TRANSPORT.map(([n, e]) => `<button class="chip ${n === F.tr ? 'on' : ''}" data-a="pick-tr" data-v="${n}">${e} ${n}</button>`).join('')}</div></div>
    <div class="fl">Purpose</div><input id="f-note" maxlength="80" placeholder="e.g. Lunch with team" autocomplete="off" value="${esc(F.note)}">
    <div class="fl">Date & time</div><input id="f-ts" type="datetime-local" value="${esc(F.ts)}">
    <div class="fl">Paid via</div>
    <div class="chips" id="f-modes">${MODES.map(m => `<button class="chip ${m === F.m ? 'on' : ''}" data-a="pick-mode" data-v="${m}">${m}</button>`).join('')}</div>
    <button class="btn big" data-a="save">Save</button>
    ${it ? '<button class="btn ghost danger" data-a="del">Delete</button>' : ''}`;
  $('#sheet').classList.remove('hidden');
  if (!it) setTimeout(() => $('#f-amt').focus(), 120);
}
const closeSheet = () => { $('#sheet').classList.add('hidden'); F = null; L = null; };

function saveForm() {
  const amt = Math.round(parseFloat($('#f-amt').value) * 100) / 100;
  if (!(amt > 0) || amt > 1e9) return toast('Enter an amount');
  const ts = $('#f-ts').value;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(ts)) return toast('Pick a date and time');
  const item = { id: F.id || uid(), amt, cat: F.cat, note: $('#f-note').value.trim(), ts: ts.slice(0, 16), m: F.m, ...(F.cat === 'Travel' && F.tr ? { tr: F.tr } : {}), u: Date.now() };
  if (F.id) {
    const old = findItem(F.id);
    if (old && old.ts.slice(0, 7) !== item.ts.slice(0, 7)) { tombstone(old); item.id = uid(); } // moved to another month
  }
  if (item.tr) { try { localStorage.setItem(LS.tr, item.tr); } catch {} }
  upsert(item);
  closeSheet(); render(); persist(); scheduleSync();
  toast(`Saved ${fmt(amt)} · ${item.cat}`);
}

function deleteForm() {
  if (!confirm('Delete this expense?')) return;
  const old = findItem(F.id); if (old) tombstone(old);
  closeSheet(); render(); persist(); scheduleSync(); toast('Deleted');
}

/* ---------- settings actions ---------- */
function touchSettings() { const s = S.db.settings; s.u = Date.now(); S.db.sdirty = true; persist(); scheduleSync(); }

function exportCsv() {
  const cell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const rows = allItems().sort((a, b) => a.ts.localeCompare(b.ts))
    .map(x => [x.ts.slice(0, 10), x.ts.slice(11, 16), x.amt, x.cat, x.tr, x.note, x.m].map(cell).join(','));
  const blob = new Blob(['\ufeff' + ['Date,Time,Amount,Area,Transport,Purpose,Paid via', ...rows].join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `expenses-${nowLocal().slice(0, 10)}.csv`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  toast(`Exported ${rows.length} expenses`);
}

/* ---------- events ---------- */
const actions = {
  setup, unlock,
  abc() { const p = $('#pin'); p.inputMode = p.inputMode === 'numeric' ? 'text' : 'numeric'; p.blur(); p.focus(); },
  sync() { clearTimeout(st); sync(); },
  tab(v) { S.ui.tab = v; S.ui.q = ''; S.ui.cat = ''; S.ui.all = false; render(); window.scrollTo(0, 0); },
  add() { S.ui.tab === 'lent' ? openLoanSheet({ kind: 'lend' }) : openSheet(); },
  close: closeSheet,
  edit(id) { openSheet(id); },
  save: saveForm, del: deleteForm,
  'pick-cat'(v, el) { F.cat = v; $('#f-trw').classList.toggle('hidden', v !== 'Travel'); el.parentNode.querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === el)); },
  'pick-mode'(v, el) { F.m = v; el.parentNode.querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === el)); },
  'pick-tr'(v, el) { F.tr = v; el.parentNode.querySelectorAll('.chip').forEach(c => c.classList.toggle('on', c === el)); },
  mprev() { S.ui.month = shiftMonth(S.ui.month, -1); render(); },
  mnext() { if (S.ui.month < curMonth()) { S.ui.month = shiftMonth(S.ui.month, 1); render(); } },
  mnow() { S.ui.month = curMonth(); render(); },
  'toggle-all'() { S.ui.all = !S.ui.all; render(); },
  fcat(v) { S.ui.cat = v; renderHistory(); },
  'add-cat'() {
    const n = $('#nc-n').value.trim(), e = $('#nc-e').value.trim() || '📦', cats = S.db.settings.cats;
    if (!n) return toast('Enter a category name');
    if (cats.some(c => c.n.toLowerCase() === n.toLowerCase())) return toast('Already exists');
    cats.push({ n, e, c: PALETTE[cats.length % PALETTE.length] });
    touchSettings(); renderSettings();
  },
  'del-cat'(v) {
    if (!confirm(`Remove "${v}"? Past expenses keep it.`)) return;
    S.db.settings.cats = S.db.settings.cats.filter(c => c.n !== v);
    touchSettings(); renderSettings();
  },
  person(v) { openPerson(v); },
  'lend-more'(v) { const p = people().find(x => x.key === v); openLoanSheet({ kind: 'lend', who: p ? p.name : '', back: true }); },
  'got-back'(v) { const p = people().find(x => x.key === v); openLoanSheet({ kind: 'repay', who: p ? p.name : '', back: true }); },
  settle: settleLoan,
  remind: remindLoan,
  'loan-edit'(v) { openLoanSheet({ id: v, back: true }); },
  lk(v, el) {
    L.k = v;
    el.parentNode.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === el));
    $('#l-title').textContent = loanTitle(); refreshFull();
  },
  lpick(v) { $('#l-who').value = v; refreshFull(); },
  lfull(v) { $('#l-amt').value = v; },
  'loan-save': saveLoan,
  'loan-del': deleteLoan,
  'show-settled'() { S.ui.settled = !S.ui.settled; renderLent(); },
  'export-loans': exportLoans,
  export: exportCsv,
  'lock-now': lock,
  async token() {
    const t = (prompt('Paste the new GitHub token') || '').trim();
    if (t.length < 20) return;
    S.token = t; localStorage.setItem(LS.tok, await seal(S.key, { t }));
    toast('Token updated'); sync();
  },
  forget() {
    if (!confirm('Remove all data and the token from this phone? Your data in GitHub is not touched.')) return;
    Object.values(LS).forEach(k => localStorage.removeItem(k));
    location.reload();
  }
};

document.addEventListener('click', e => {
  if (e.target.id === 'sheet') return closeSheet();
  const el = e.target.closest('[data-a]'); if (!el) return;
  const fn = actions[el.dataset.a]; if (fn) fn(el.dataset.v, el);
});
document.addEventListener('input', e => {
  if (e.target.id === 'q') { S.ui.q = e.target.value; updateHistList(); }
  else if (e.target.id === 'l-who') refreshFull();
  else if (e.target.id === 'f-amt' || e.target.id === 'l-amt') e.target.value = e.target.value.replace(/[^0-9.]/g, '').replace(/(\..*)\./g, '$1');
});
document.addEventListener('change', e => {
  if (e.target.id === 'budget') {
    const v = Math.max(0, Math.round(parseFloat(e.target.value) || 0));
    S.db.settings.budget = v; e.target.value = v || ''; touchSettings(); toast('Budget saved');
  }
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('#sheet').classList.contains('hidden')) return closeSheet();
  if (e.key !== 'Enter') return;
  if (e.target.id === 'pin') unlock();
  else if (e.target.id === 's-pin2') setup();
  else if (F && (e.target.id === 'f-amt' || e.target.id === 'f-note')) saveForm();
  else if (L && ['l-who', 'l-amt', 'l-note'].includes(e.target.id)) saveLoan();
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { S.hiddenAt = Date.now(); persist(true); }
  else if (S.key) {
    if (Date.now() - S.hiddenAt > LOCK_MS) lock();
    else if (Date.now() - (S.db.last || 0) > 60000) sync();
  }
});
window.addEventListener('online', () => sync());
window.addEventListener('offline', () => S.key && setSync('off', 'Offline'));

/* ---------- boot ---------- */
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
try { S.cfg = JSON.parse(localStorage.getItem(LS.cfg) || 'null'); } catch { S.cfg = null; }
if (S.cfg && localStorage.getItem(LS.tok)) { show('lock'); $('#pin').focus(); } else show('setup');
})();
