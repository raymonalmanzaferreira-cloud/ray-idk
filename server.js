const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database('ray.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    ua TEXT,
    referer TEXT,
    path TEXT,
    ts INTEGER NOT NULL
  );
`);

const ADMIN_PASSWORD = process.env.RAY_PASSWORD || 'change-me-now';
const SESSION_SECRET = process.env.RAY_SECRET || crypto.randomBytes(32).toString('hex');

app.set('trust proxy', true); // needed if you sit behind nginx/caddy/cloudflare
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 12 }
}));

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

// Public tracker — every non-admin hit gets logged
app.get('/', (req, res) => {
  if (req.session && req.session.admin) return res.redirect('/admin');

  db.prepare(
    'INSERT INTO hits (ip, ua, referer, path, ts) VALUES (?, ?, ?, ?, ?)'
  ).run(
    clientIp(req),
    req.headers['user-agent'] || '',
    req.headers['referer'] || '',
    req.path,
    Date.now()
  );

  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><title>ray.idk</title>
<style>body{background:#0b0b0d;color:#c9c7c1;font:16px/1.5 ui-monospace,Menlo,monospace;
display:grid;place-items:center;min-height:100vh;margin:0}
h1{font-weight:400;letter-spacing:.2em;text-transform:lowercase}</style></head>
<body><h1>ray.idk</h1></body></html>`);
});

// Login
app.get('/login', (req, res) => {
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<title>ray.idk</title><style>body{background:#0b0b0d;color:#c9c7c1;
font:16px/1.5 ui-monospace,Menlo,monospace;display:grid;place-items:center;
min-height:100vh;margin:0}form{display:flex;gap:.5em}input,button{background:#15151a;
color:#c9c7c1;border:1px solid #333;padding:.6em .8em;font:inherit}
button{cursor:pointer}</style></head><body>
<form method="post" action="/login">
<input type="password" name="pw" placeholder="password" autofocus>
<button>enter</button></form></body></html>`);
});

app.post('/login', (req, res) => {
  const given = String(req.body.pw || '');
  const a = Buffer.from(given);
  const b = Buffer.from(ADMIN_PASSWORD);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (ok) {
    req.session.admin = true;
    return res.redirect('/admin');
  }
  res.status(401).redirect('/login');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Admin dashboard — gated
app.get('/admin', (req, res) => {
  if (!req.session || !req.session.admin) return res.redirect('/login');

  const rows = db.prepare(
    'SELECT ip, ua, referer, path, ts FROM hits ORDER BY ts DESC LIMIT 500'
  ).all();

  const body = rows.map(r => `
    <tr>
      <td>${new Date(r.ts).toISOString()}</td>
      <td>${escapeHtml(r.ip)}</td>
      <td>${escapeHtml(r.path)}</td>
      <td>${escapeHtml(r.referer || '—')}</td>
      <td class="ua">${escapeHtml(r.ua || '—')}</td>
    </tr>`).join('');

  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<title>ray.idk — admin</title>
<style>body{background:#0b0b0d;color:#c9c7c1;
font:13px/1.5 ui-monospace,Menlo,monospace;margin:0;padding:2em}
h1{font-weight:400;letter-spacing:.2em;text-transform:lowercase;margin:0 0 1em}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:.5em .8em;border-bottom:1px solid #1e1e24;vertical-align:top}
th{color:#7a7772;font-weight:400;text-transform:lowercase;letter-spacing:.1em}
.ua{color:#8a8882;font-size:12px}
form{position:fixed;top:1em;right:1em}
button{background:#15151a;color:#c9c7c1;border:1px solid #333;padding:.4em .7em;
font:inherit;cursor:pointer}</style></head><body>
<form method="post" action="/logout"><button>log out</button></form>
<h1>ray.idk</h1>
<table><thead><tr><th>time</th><th>ip</th><th>path</th><th>referer</th><th>user agent</th></tr></thead>
<tbody>${body || '<tr><td colspan="5">no hits yet</td></tr>'}</tbody>
</table></body></html>`);
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ray.idk on :${PORT}`));
