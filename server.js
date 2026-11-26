'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');

// ---------- tiny .env loader (no extra dependency) ----------
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  });
} catch (e) { /* no .env file, use real environment variables */ }

const PORT = Number(process.env.PORT) || 3000;
const vercelHost = process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL;
const BASE_URL = (process.env.BASE_URL || (vercelHost ? `https://${vercelHost}` : `http://localhost:${PORT}`)).replace(/\/+$/, '');
const SECRET = process.env.SESSION_SECRET || '';
const SECURE_COOKIE = BASE_URL.startsWith('https://') || process.env.VERCEL === '1';
const DB_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DB = process.env.MONGODB_DB || 'dinner';

if (SECRET.length < 16) {
  console.error('Set SESSION_SECRET in .env (at least 16 characters).');
  process.exit(1);
}

// ---------- storage (JSON file, written atomically) ----------
let db = { admins: [], guests: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { /* first run */ }
db.admins = db.admins || []; db.guests = db.guests || [];
let adminsCollection;
let guestsCollection;
let storageReady;

function getMongoClient() {
  if (!globalThis.__dinnerMongoClientPromise) {
    const client = new MongoClient(MONGODB_URI, {
      maxPoolSize: 5, // Keep each low-volume serverless instance's pool small.
      maxIdleTimeMS: 10000 // Release idle connections between bursts.
    });
    globalThis.__dinnerMongoClientPromise = client.connect().catch(error => {
      globalThis.__dinnerMongoClientPromise = null;
      throw error;
    });
  }
  return globalThis.__dinnerMongoClientPromise;
}

async function initializeStorage() {
  if (!MONGODB_URI) {
    if (process.env.VERCEL === '1') throw new Error('MONGODB_URI must be configured for Vercel deployments.');
    return;
  }
  if (!storageReady) {
    storageReady = (async () => {
      const client = await getMongoClient();
      const mongoDb = client.db(MONGODB_DB);
      adminsCollection = mongoDb.collection('admins');
      guestsCollection = mongoDb.collection('guests');
      await adminsCollection.createIndex({ username: 1 }, { unique: true });
      await guestsCollection.createIndex({ id: 1 }, { unique: true });
      await guestsCollection.createIndex({ token: 1 }, { unique: true });

      if (await adminsCollection.countDocuments() === 0) {
        const username = process.env.FIRST_ADMIN_USERNAME;
        const password = process.env.FIRST_ADMIN_PASSWORD;
        if (username && password) {
          try { await addAdmin(username, password); }
          catch (error) {
            if (error.status !== 400 || await adminsCollection.countDocuments() === 0) throw error;
          }
        } else console.warn('No admin exists. Set FIRST_ADMIN_USERNAME and FIRST_ADMIN_PASSWORD in the deployment environment.');
      }
    })().catch(error => {
      storageReady = null;
      throw error;
    });
  }
  await storageReady;
}

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
function invalidInput(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}
function makeAdmin(username, password) {
  username = String(username || '').trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw invalidInput('Username must be 3-32 characters: letters, numbers, dot, dash or underscore.');
  if (String(password || '').length < 8) throw invalidInput('Password must be at least 8 characters.');
  return { username, ...hashPassword(password), created: new Date().toISOString() };
}
function addLocalAdmin(username, password) {
  const admin = makeAdmin(username, password);
  if (db.admins.some(a => a.username === admin.username)) throw invalidInput('That username already exists.');
  db.admins.push(admin);
  try { save(); }
  catch (error) { db.admins.pop(); throw error; }
  return admin.username;
}
async function addAdmin(username, password) {
  const admin = makeAdmin(username, password);
  if (!MONGODB_URI) {
    if (db.admins.some(a => a.username === admin.username)) throw invalidInput('That username already exists.');
    db.admins.push(admin);
    try { save(); }
    catch (error) { db.admins.pop(); throw error; }
    return admin.username;
  }
  try { await adminsCollection.insertOne(admin); }
  catch (error) {
    if (error.code === 11000) throw invalidInput('That username already exists.');
    throw error;
  }
  return admin.username;
}
async function findAdmin(username) {
  if (MONGODB_URI) return adminsCollection.findOne({ username });
  return db.admins.find(a => a.username === username) || null;
}
async function listAdmins() {
  if (MONGODB_URI) return adminsCollection.find({}, { projection: { _id: 0, username: 1, created: 1 } }).toArray();
  return db.admins.map(a => ({ username: a.username, created: a.created }));
}
async function listGuests() {
  if (MONGODB_URI) return guestsCollection.find({}).toArray();
  return db.guests;
}
async function findGuestByToken(token) {
  if (MONGODB_URI) return guestsCollection.findOne({ token });
  return db.guests.find(g => g.token === token) || null;
}
async function addGuest(guest) {
  if (MONGODB_URI) return guestsCollection.insertOne(guest);
  db.guests.push(guest);
  try { save(); }
  catch (error) { db.guests.pop(); throw error; }
}
async function removeGuest(id) {
  if (MONGODB_URI) return (await guestsCollection.deleteOne({ id })).deletedCount > 0;
  const index = db.guests.findIndex(g => g.id === id);
  if (index < 0) return false;
  const [guest] = db.guests.splice(index, 1);
  try { save(); }
  catch (error) { db.guests.splice(index, 0, guest); throw error; }
  return true;
}
async function recordGuestOpen(guest) {
  const lastOpened = new Date().toISOString();
  if (MONGODB_URI) {
    await guestsCollection.updateOne({ id: guest.id }, { $inc: { opens: 1 }, $set: { lastOpened } });
    return;
  }
  guest.opens = (guest.opens || 0) + 1;
  guest.lastOpened = lastOpened;
  save();
}

// First start: create the first admin from .env
if (!MONGODB_URI && process.env.VERCEL !== '1' && db.admins.length === 0) {
  const u = process.env.FIRST_ADMIN_USERNAME, p = process.env.FIRST_ADMIN_PASSWORD;
  if (u && p) { try { addLocalAdmin(u, p); console.log(`Created first admin "${u}".`); } catch (e) { console.error(e.message); } }
  else console.warn('No admin exists. Set FIRST_ADMIN_USERNAME and FIRST_ADMIN_PASSWORD in .env and restart.');
}

// ---------- signed session cookie ----------
const b64 = s => Buffer.from(s).toString('base64url');
const sign = s => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeSession(username) {
  const body = b64(JSON.stringify({ u: username, exp: Date.now() + 7 * 24 * 3600 * 1000 }));
  return body + '.' + sign(body);
}
async function readSession(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig) return null;
  const good = sign(body);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  let d;
  try {
    d = JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch (e) { return null; }
  if (!d || typeof d.u !== 'string' || typeof d.exp !== 'number' || d.exp < Date.now()) return null;
  return await findAdmin(d.u) ? d.u : null;
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

const asyncHandler = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
function withStorage(req, res, next) {
  initializeStorage().then(next).catch(next);
}

// login with simple rate limiting
const attempts = new Map();
app.post('/api/login', withStorage, asyncHandler(async (req, res) => {
  const now = Date.now(), rec = attempts.get(req.ip) || { n: 0, reset: now + 15 * 60 * 1000 };
  if (now > rec.reset) { rec.n = 0; rec.reset = now + 15 * 60 * 1000; }
  if (rec.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const username = String((req.body || {}).username || '').trim().toLowerCase();
  const admin = await findAdmin(username);
  const ok = admin && checkPassword(String((req.body || {}).password || ''), admin);
  if (!ok) { rec.n++; attempts.set(req.ip, rec); return res.status(401).json({ error: 'Wrong username or password.' }); }
  attempts.delete(req.ip);
  res.set('Set-Cookie', cookie(makeSession(username), 7 * 24 * 3600));
  res.json({ username });
}));
app.post('/api/logout', (req, res) => { res.set('Set-Cookie', cookie('', 0)); res.json({ ok: true }); });

// everything below needs an admin session
function needAdmin(req, res, next) {
  withStorage(req, res, () => {
    readSession(req).then(username => {
      if (!username) return res.status(401).json({ error: 'Please sign in.' });
      req.admin = username;
      next();
    }).catch(next);
  });
}
const slugFor = name => String(name || '')
  .normalize('NFKD')
  .replace(/[^a-z0-9]+/gi, '-')
  .replace(/^-+|-+$/g, '')
  .toLowerCase()
  .slice(0, 40) || 'guest';
const linkFor = g => `${BASE_URL}/i/${slugFor(g.name)}/${g.token}`;
const publicGuest = g => ({ id: g.id, name: g.name, link: linkFor(g), created: g.created, opens: g.opens || 0, lastOpened: g.lastOpened || null });

app.get('/api/me', needAdmin, (req, res) => res.json({ username: req.admin }));

app.get('/api/guests', needAdmin, asyncHandler(async (req, res) => res.json((await listGuests()).map(publicGuest))));
app.post('/api/guests', needAdmin, asyncHandler(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().replace(/\s+/g, ' ');
  if (!name || name.length > 60) return res.status(400).json({ error: 'Enter a name (up to 60 characters).' });
  const g = { id: crypto.randomUUID(), name, token: crypto.randomBytes(9).toString('base64url'), created: new Date().toISOString(), addedBy: req.admin, opens: 0 };
  await addGuest(g);
  res.status(201).json(publicGuest(g));
}));
app.delete('/api/guests/:id', needAdmin, asyncHandler(async (req, res) => {
  if (!await removeGuest(req.params.id)) return res.status(404).json({ error: 'Guest not found.' });
  res.json({ ok: true });
}));

app.get('/api/admins', needAdmin, asyncHandler(async (req, res) => res.json(await listAdmins())));
app.post('/api/admins', needAdmin, asyncHandler(async (req, res) => {
  res.status(201).json({ username: await addAdmin((req.body || {}).username, (req.body || {}).password) });
}));
app.delete('/api/admins/:username', needAdmin, asyncHandler(async (req, res) => {
  const u = req.params.username.toLowerCase();
  if (u === req.admin) return res.status(400).json({ error: 'You cannot remove yourself.' });
  if (MONGODB_URI) {
    if ((await adminsCollection.deleteOne({ username: u })).deletedCount === 0) return res.status(404).json({ error: 'Admin not found.' });
  } else {
    const i = db.admins.findIndex(a => a.username === u);
    if (i < 0) return res.status(404).json({ error: 'Admin not found.' });
    const [admin] = db.admins.splice(i, 1);
    try { save(); }
    catch (error) { db.admins.splice(i, 0, admin); throw error; }
  }
  res.json({ ok: true });
}));

// ---------- pages ----------
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const readEvent = () => JSON.parse(fs.readFileSync(path.join(__dirname, 'event.json'), 'utf8'));
const template = () => fs.readFileSync(path.join(__dirname, 'views', 'invite.html'), 'utf8');
const renderInvite = name => {
  const ev = readEvent();
  const vars = { NAME: name, TITLE: ev.title, DAYNAME: ev.dayName, DAY: ev.day, MONTHYEAR: ev.monthYear, TIME: ev.time, VENUE: ev.venue, DRESS: ev.dress, BASE_URL };
  return template().replace(/\{\{(\w+)\}\}/g, (_, k) => esc(vars[k] ?? ''));
};

app.get('/admin', (req, res) => res.set('Cache-Control', 'no-store').sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/programme-flow', (req, res) => res.set('Cache-Control', 'no-store').sendFile(path.join(__dirname, 'programme-flow-v2.html')));
app.get('/', (req, res) => res.status(404).set('Cache-Control', 'no-store').type('html').send(
  '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found</title><body style="font-family:system-ui;background:#0c2a23;color:#f3ead7;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><p>This invitation link is not valid.<br>Please use the personal link sent to you.</p>'
));

const openInvite = async (req, res) => {
  const g = await findGuestByToken(req.params.token);
  if (!g) return res.status(404).type('html').send('<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Not found</title><body style="font-family:system-ui;background:#0c2a23;color:#f3ead7;display:grid;place-items:center;min-height:100vh;margin:0;text-align:center"><p>This invitation link is not valid.<br>Please ask the host for a new one.</p>');
  if (!/bot|crawl|spider|whatsapp|facebookexternalhit|telegram|preview|slack/i.test(req.headers['user-agent'] || '')) {
    await recordGuestOpen(g);
  }
  res.set('Cache-Control', 'no-store').type('html').send(renderInvite(g.name));
};

app.get('/i/:name/:token', withStorage, asyncHandler(openInvite));
app.get('/i/:token', withStorage, asyncHandler(openInvite));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600 ? error.status : 500;
  if (status >= 500) console.error(`Request failed for ${req.method} ${req.path}:`, error);
  res.status(status).json({ error: status === 500 ? 'Request failed. Check the server logs and database configuration.' : error.message });
});

app.listen(PORT, () => console.log(`Invitation site running at ${BASE_URL} (port ${PORT}). Admin panel: ${BASE_URL}/admin`));
