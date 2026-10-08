// Phone copy of the start page. The links arrive encrypted (data.enc, written by the extension's
// "Publish to phone"); they are decrypted here, in the browser, with a key made from your password.
// The key is kept on this phone (IndexedDB, not readable as text), so the password is asked once.

const app = document.getElementById('app');
const ENC_CACHE = 'sp:enc';
const UI_KEY = 'sp:ui';

// ---------- small helpers ----------

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c);
  return el;
}

const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch {} };
const lsDel = (k) => { try { localStorage.removeItem(k); } catch {} };
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function status(text, extra) {
  app.replaceChildren(h('p', { class: 'status' }, text), extra || '');
}

// ---------- the key, kept in IndexedDB ----------

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('start-key', 1);
    req.onupgradeneeded = () => req.result.createObjectStore('k');
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function keyOp(mode, fn) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const req = fn(db.transaction('k', mode).objectStore('k'));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
const loadKey = () => keyOp('readonly', (s) => s.get('key')).catch(() => null);
const saveKey = (v) => keyOp('readwrite', (s) => s.put(v, 'key')).catch(() => {});
const forgetKey = () => keyOp('readwrite', (s) => s.delete('key')).catch(() => {});

// ---------- decryption ----------

async function deriveKey(password, env) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: env.kdf.hash, salt: fromB64(env.kdf.salt), iterations: env.kdf.iter },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}

async function decrypt(env, key) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(env.iv) }, key, fromB64(env.data));
  const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  return JSON.parse(text);
}

// ---------- start ----------

let data = null;
const ui = (() => { try { return JSON.parse(lsGet(UI_KEY)) || {}; } catch { return {}; } })();
ui.closed = ui.closed || {};
const saveUi = () => lsSet(UI_KEY, JSON.stringify(ui));

async function start() {
  if (!crypto.subtle || typeof DecompressionStream === 'undefined') return status('This browser is too old for this page.');
  const saved = await loadKey();
  const cached = lsGet(ENC_CACHE);
  // Show the last copy at once; the fresh one replaces it when it arrives.
  if (saved && cached) {
    try { const env = JSON.parse(cached); if (env.kdf.salt === saved.salt) render(await decrypt(env, saved.key)); } catch {}
  }
  let fresh;
  try {
    const res = await fetch('data.enc?t=' + Date.now(), { cache: 'no-store' });
    if (res.status === 404) return data || status('Nothing published yet. On the computer: Settings → Import & backup → Publish to phone.');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    fresh = await res.text();
  } catch {
    if (!data) status('Offline — could not load your links.');
    return;
  }
  if (data && fresh === cached) return;
  const env = JSON.parse(fresh);
  if (saved && saved.salt === env.kdf.salt) {
    try {
      render(await decrypt(env, saved.key));
      lsSet(ENC_CACHE, fresh);
      return;
    } catch {}
  }
  askPassword(env, fresh);
}

function askPassword(env, text) {
  const input = h('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password', required: true });
  const err = h('div', { class: 'err' });
  const btn = h('button', { class: 'btn', type: 'submit' }, 'Unlock');
  const form = h('form', { class: 'unlock', onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true;
    err.textContent = '';
    try {
      const key = await deriveKey(input.value, env);
      const payload = await decrypt(env, key);
      await saveKey({ salt: env.kdf.salt, key });
      lsSet(ENC_CACHE, text);
      render(payload);
    } catch {
      err.textContent = 'Wrong password';
      btn.disabled = false;
      input.select();
    }
  } },
  h('h1', null, '🔒 Start'),
  h('p', null, data ? 'The password was changed on the computer. Enter the new one.' : 'Enter the password you set in the extension.'),
  input, err, btn);
  app.replaceChildren(form);
  input.focus();
}

// ---------- rendering ----------

const TILE_COLORS = ['#ef4444', '#f97316', '#d97706', '#65a30d', '#16a34a', '#0d9488', '#0891b2', '#2563eb', '#4f46e5', '#7c3aed', '#c026d3', '#db2777', '#475569'];
const hash = (s) => { let x = 0; for (let i = 0; i < s.length; i++) x = (x * 31 + s.charCodeAt(i)) | 0; return Math.abs(x); };
const hostOf = (u) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return ''; } };

function readableOn(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || '');
  if (!m) return '';
  const n = parseInt(m[1], 16);
  return (0.299 * ((n >> 16) & 255) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255 > 0.6 ? '#111827' : '#ffffff';
}

const iconSrc = (ref) => (ref && ref[0] === '#' ? data.icons[+ref.slice(1)] : ref);

function letterTile(title, url) {
  const label = (title || hostOf(url) || '?').trim();
  return h('span', { class: 'ico', style: { background: TILE_COLORS[hash(hostOf(url) || label) % TILE_COLORS.length] } }, [...label][0]?.toUpperCase() || '?');
}

function linkIcon(it) {
  if (it.i && it.i.startsWith('emoji:')) return h('span', { class: 'ico emo' }, it.i.slice(6));
  const host = hostOf(it.u);
  const src = iconSrc(it.i) || (host ? `https://www.google.com/s2/favicons?domain=${encodeURIComponent(host)}&sz=128` : '');
  if (!src) return letterTile(it.t, it.u);
  const img = h('img', { class: 'ico', src, alt: '', loading: 'lazy', decoding: 'async', referrerpolicy: 'no-referrer' });
  img.addEventListener('error', () => img.replaceWith(letterTile(it.t, it.u)), { once: true });
  return img;
}

function groupIcon(ref) {
  if (!ref) return null;
  if (ref.startsWith('emoji:')) return h('span', { class: 'gicon emo' }, ref.slice(6));
  const img = h('img', { class: 'gicon', src: iconSrc(ref), alt: '' });
  img.addEventListener('error', () => img.remove(), { once: true });
  return img;
}

function linkEl(it, showDesc) {
  return h('a', { class: 'bm', href: it.u, rel: 'noopener noreferrer', title: it.u },
    linkIcon(it),
    h('span', { class: 't', dir: 'auto' }, it.t || it.u, showDesc && it.d ? h('span', { class: 'd', dir: 'auto' }, it.d) : null));
}

function itemsEl(items, g) {
  const box = h('div', { class: g.view === 'list' ? 'list' : 'grid' });
  for (const it of items) {
    if (!it.items) { box.append(linkEl(it, g.desc)); continue; }
    const folder = h('div', { class: 'folder' });
    folder.append(
      h('button', { class: 'fhead', type: 'button', onclick: () => folder.classList.toggle('open') },
        h('span', { class: 'chev' }, '▸'), h('span', null, '📁'), h('span', { dir: 'auto' }, it.t)),
      h('div', { class: 'fbody' }, itemsEl(it.items, g)));
    box.append(folder);
  }
  if (!items.length) box.append(h('div', { class: 'empty' }, 'Empty'));
  return box;
}

function groupEl(g, pageName) {
  const key = pageName + '/' + g.title;
  const el = h('section', { class: 'group' + (ui.closed[key] ? ' closed' : '') });
  const head = h('button', { class: 'ghead', type: 'button', onclick: () => {
    el.classList.toggle('closed');
    if (el.classList.contains('closed')) ui.closed[key] = 1; else delete ui.closed[key];
    saveUi();
  } }, groupIcon(g.icon), h('span', { class: 'gtitle', dir: 'auto' }, g.title), h('span', { class: 'chev' }, '▾'));
  if (g.color) {
    head.style.setProperty('--gcolor', g.color);
    head.style.setProperty('--gtext', readableOn(g.color) || '#fff');
  }
  el.append(head, h('div', { class: 'gbody' }, itemsEl(g.items, g)));
  return el;
}

function flatLinks(items, out = []) {
  for (const it of items) it.items ? flatLinks(it.items, out) : out.push(it);
  return out;
}

let query = '';
let listEl = null;

function renderList() {
  const page = data.pages[Math.min(ui.page || 0, data.pages.length - 1)] || { name: '', groups: [] };
  const q = query.trim().toLowerCase();
  if (!q) {
    listEl.replaceChildren(...page.groups.map((g) => groupEl(g, page.name)));
    if (!page.groups.length) listEl.append(h('p', { class: 'empty' }, 'No groups on this page.'));
    return;
  }
  const hits = [];
  for (const p of data.pages) for (const g of p.groups) for (const it of flatLinks(g.items)) {
    if ([it.t, it.u, it.d].some((s) => s && s.toLowerCase().includes(q))) hits.push(it);
  }
  listEl.replaceChildren(h('section', { class: 'group' },
    hits.length ? h('div', { class: 'list' }, hits.slice(0, 60).map((it) => linkEl(it, true))) : h('div', { class: 'empty' }, 'No matching links — press Enter to search the web')));
}

function render(payload) {
  data = payload;
  if (data.accent) document.documentElement.style.setProperty('--accent', data.accent);
  const input = h('input', { type: 'search', placeholder: 'Search links or the web', enterkeyhint: 'search', autocomplete: 'off', dir: 'auto', value: query });
  input.addEventListener('input', () => { query = input.value; renderList(); });
  const form = h('form', { class: 'search', onsubmit: (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    location.href = /^https?:\/\//i.test(q) ? q : /^[\w-]+(\.[\w-]+)+(\/\S*)?$/.test(q) ? 'https://' + q : (data.search || 'https://www.google.com/search?q=%s').replace('%s', encodeURIComponent(q));
  } }, input);
  const tabs = data.pages.length > 1 ? h('nav', { class: 'tabs' }, data.pages.map((p, i) => h('button', {
    type: 'button', class: 'tab' + (i === (ui.page || 0) ? ' on' : ''),
    onclick: () => { ui.page = i; saveUi(); render(data); },
  }, p.name))) : null;
  listEl = h('div');
  const updated = data.at ? new Date(data.at).toLocaleString() : '';
  app.replaceChildren(
    h('header', { class: 'top' },
      data.avatar ? h('img', { class: 'avatar', src: iconSrc(data.avatar), alt: '' }) : null,
      h('div', { class: 'greet', dir: 'auto' }, data.greeting || 'Start')),
    form, tabs, listEl,
    h('footer', { class: 'foot' },
      updated ? h('span', null, 'Updated ' + updated) : null,
      h('button', { class: 'ghost', type: 'button', onclick: async () => {
        await forgetKey();
        lsDel(ENC_CACHE);
        location.reload();
      } }, 'Lock this phone (forget the password)')));
  renderList();
}

start();
