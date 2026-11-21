'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- tiny .env loader (no extra dependency) ----------
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  });
} catch (e) { /* no .env file, use real environment variables */ }

const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const SECRET = process.env.SESSION_SECRET || '';
const SECURE_COOKIE = BASE_URL.startsWith('https://');
const DB_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');

if (SECRET.length < 16) {
  console.error('Set SESSION_SECRET in .env (at least 16 characters).');
  process.exit(1);
}

// ---------- storage (JSON file, written atomically) ----------
let db = { admins: [], guests: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { /* first run */ }
db.admins = db.admins || []; db.guests = db.guests || [];
function save() {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

// ---------- passwords ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function checkPassword(password, admin) {
  const a = Buffer.from(hashPassword(password, admin.salt).hash, 'hex');
  const b = Buffer.from(admin.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function addAdmin(username, password) {
  username = String(username || '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw new Error('Username must be 3-32 characters: letters, numbers, dot, dash or underscore.');
  if (String(password || '').length < 8) throw new Error('Password must be at least 8 characters.');
  if (db.admins.some(a => a.username === username)) throw new Error('That username already exists.');
  db.admins.push({ username, ...hashPassword(password), created: new Date().toISOString() });
  save();
  return username;
}

// First start: create the first admin from .env
if (db.admins.length === 0) {
  const u = process.env.FIRST_ADMIN_USERNAME, p = process.env.FIRST_ADMIN_PASSWORD;
  if (u && p) { try { addAdmin(u, p); console.log(`Created first admin "${u}".`); } catch (e) { console.error(e.message); } }
  else console.warn('No admin exists. Set FIRST_ADMIN_USERNAME and FIRST_ADMIN_PASSWORD in .env and restart.');
}

// ---------- signed session cookie ----------
const b64 = s => Buffer.from(s).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeSession(username) {
  const body = b64(JSON.stringify({ u: username, exp: Date.now() + 7 * 24 * 3600 * 1000 }));
  return body + '.' + sign(body);
}
function readSession(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig) return null;
  const good = sign(body);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try {
    const d = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (d.exp < Date.now()) return null;
    return db.admins.find(a => a.username === d.u) ? d.u : null;
  } catch (e) { return null; }
}
const cookie = (value, maxAge) =>
  `sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${SECURE_COOKIE ? '; Secure' : ''}`;

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'X-Robots-Tag': 'noindex, nofollow',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
  });
  next();
});
app.use(express.json({ limit: '10kb' }));
// state-changing API calls must be JSON (blocks cross-site form posts)
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && !req.is('application/json')) return res.status(415).json({ error: 'JSON only' });
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { index: false, maxAge: '1d' }));

// login with simple rate limiting
const attempts = new Map();
app.post('/api/login', (req, res) => {
  const now = Date.now(), rec = attempts.get(req.ip) || { n: 0, reset: now + 15 * 60 * 1000 };
  if (now > rec.reset) { rec.n = 0; rec.reset = now + 15 * 60 * 1000; }
  if (rec.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const username = String((req.body || {}).username || '').trim().toLowerCase();
  const admin = db.admins.find(a => a.username === username);
  const ok = admin && checkPassword(String((req.body || {}).password || ''), admin);
  if (!ok) { rec.n++; attempts.set(req.ip, rec); return res.status(401).json({ error: 'Wrong username or password.' }); }
  attempts.delete(req.ip);
  res.set('Set-Cookie', cookie(makeSession(username), 7 * 24 * 3600));
  res.json({ username });
});
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', cookie('', 0)); res.json({ ok: true }); });

// everything below needs an admin session
function needAdmin(req, res, next) {
  const u = readSession(req);
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  req.admin = u; next();
}
const linkFor = g => `${BASE_URL}/i/${g.token}`;
const publicGuest = g => ({ id: g.id, name: g.name, link: linkFor(g), created: g.created, opens: g.opens || 0, lastOpened: g.lastOpened || null });

app.get('/api/me', needAdmin, (req, res) => res.json({ username: req.admin }));

app.get('/api/guests', needAdmin, (req, res) => res.json(db.guests.map(publicGuest)));
app.post('/api/guests', needAdmin, (req, res) => {
  const name = String((req.body || {}).name || '').trim().replace(/\s+/g, ' ');
  if (!name || name.length > 60) return res.status(400).json({ error: 'Enter a name (up to 60 characters).' });
  const g = { id: crypto.randomUUID(), name, token: crypto.randomBytes(9).toString('base64url'), created: new Date().toISOString(), addedBy: req.admin, opens: 0 };
  db.guests.push(g); save();
  res.status(201).json(publicGuest(g));
});
app.delete('/api/guests/:id', needAdmin, (req, res) => {
  const i = db.guests.findIndex(g => g.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Guest not found.' });
  db.guests.splice(i, 1); save(); res.json({ ok: true });
});

app.get('/api/admins', needAdmin, (req, res) => res.json(db.admins.map(a => ({ username: a.username, created: a.created }))));
app.post('/api/admins', needAdmin, (req, res) => {
  try { res.status(201).json({ username: addAdmin((req.body || {}).username, (req.body || {}).password) }); }
  catch (e) { res.status(400).json({ error: e.message }); }
});
app.delete('/api/admins/:username', needAdmin, (req, res) => {
  const u = req.params.username.toLowerCase();
  if (u === req.admin) return res.status(400).json({ error: 'You cannot remove yourself.' });
  const i = db.admins.findIndex(a => a.username === u);
  if (i < 0) return res.status(404).json({ error: 'Admin not found.' });
  db.admins.splice(i, 1); save(); res.json({ ok: true });
});

// ---------- pages ----------
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const readEvent = () => JSON.parse(fs.readFileSync(path.join(__dirname, 'event.json'), 'utf8'));
const template = () => fs.readFileSync(path.join(__dirname, 'views', 'invite.html'), 'utf8');

app.get('/admin', (req, res) => res.set('Cache-Control', 'no-store').sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.type('html').send('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invitation</title><body style="font-family:system-ui;background:#0c2a23;color:#f3ead7;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><p>This is a private invitation.<br>Please open the personal link you were sent.</p>'));

app.get('/i/:token', (req, res) => {
  const g = db.guests.find(x => x.token === req.params.token);
  if (!g) return res.status(404).type('html').send('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found</title><body style="font-family:system-ui;background:#0c2a23;color:#f3ead7;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><p>This invitation link is not valid.<br>Please ask the host for a new one.</p>');
  if (!/bot|crawl|spider|whatsapp|facebookexternalhit|telegram|preview|slack/i.test(req.headers['user-agent'] || '')) {
    g.opens = (g.opens || 0) + 1; g.lastOpened = new Date().toISOString(); save();
  }
  const ev = readEvent();
  const vars = { NAME: g.name, TITLE: ev.title, DAYNAME: ev.dayName, DAY: ev.day, MONTHYEAR: ev.monthYear, TIME: ev.time, VENUE: ev.venue, DRESS: ev.dress, BASE_URL };
  const html = template().replace(/\{\{(\w+)\}\}/g, (_, k) => esc(vars[k] ?? ''));
  res.set('Cache-Control', 'no-store').type('html').send(html);
});

app.listen(PORT, () => console.log(`Invitation site running at ${BASE_URL} (port ${PORT}). Admin panel: ${BASE_URL}/admin`));
