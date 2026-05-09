const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const db = new DatabaseSync(path.join(__dirname, 'data.db'));
const JWT_SECRET = process.env.JWT_SECRET || 'newspaper-tracker-secret-change-in-production';
const PORT = process.env.PORT || 3000;

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS newspapers (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    prices TEXT NOT NULL DEFAULT '{}',
    monthly_delivery_charge REAL NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS deliveries (
    user_id INTEGER NOT NULL,
    date_key TEXT NOT NULL,
    np_id TEXT NOT NULL,
    qty REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, date_key, np_id)
  );
`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
  const token = jwt.sign({ userId: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  const token = jwt.sign({ userId: user.id, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username });
});

function parsePriceHistory(pricesJson, fallbackCharge) {
  const parsed = JSON.parse(pricesJson);
  if (Array.isArray(parsed)) return parsed;
  // Migrate old flat format to history array
  return [{ from: '2000-01-01', prices: parsed, monthlyDeliveryCharge: fallbackCharge || 0 }];
}

app.get('/api/newspapers', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM newspapers WHERE user_id = ?').all(req.user.userId);
  res.json(rows.map(r => ({
    id: r.id,
    name: r.name,
    priceHistory: parsePriceHistory(r.prices, r.monthly_delivery_charge)
  })));
});

app.post('/api/newspapers', requireAuth, (req, res) => {
  const { id, name, prices, monthlyDeliveryCharge } = req.body;
  if (!id || !name) return res.status(400).json({ error: 'id and name required' });
  const existing = db.prepare('SELECT id FROM newspapers WHERE user_id = ? AND name = ?').get(req.user.userId, name);
  if (existing) return res.status(409).json({ error: 'An item with that name already exists' });
  const priceHistory = [{ from: '2000-01-01', prices: prices || {}, monthlyDeliveryCharge: monthlyDeliveryCharge || 0 }];
  db.prepare('INSERT INTO newspapers (id, user_id, name, prices, monthly_delivery_charge) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.user.userId, name, JSON.stringify(priceHistory), monthlyDeliveryCharge || 0);
  res.json({ ok: true });
});

app.put('/api/newspapers/:id', requireAuth, (req, res) => {
  const { name, newRateEntry } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const conflict = db.prepare('SELECT id FROM newspapers WHERE user_id = ? AND name = ? AND id != ?').get(req.user.userId, name, req.params.id);
  if (conflict) return res.status(409).json({ error: 'An item with that name already exists' });
  const row = db.prepare('SELECT prices, monthly_delivery_charge FROM newspapers WHERE id=? AND user_id=?').get(req.params.id, req.user.userId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  let history = parsePriceHistory(row.prices, row.monthly_delivery_charge);
  if (newRateEntry) {
    history = history.filter(e => e.from !== newRateEntry.from);
    history.push(newRateEntry);
    history.sort((a, b) => a.from.localeCompare(b.from));
  }
  const latestCharge = history[history.length - 1]?.monthlyDeliveryCharge || 0;
  db.prepare('UPDATE newspapers SET name=?, prices=?, monthly_delivery_charge=? WHERE id=? AND user_id=?')
    .run(name, JSON.stringify(history), latestCharge, req.params.id, req.user.userId);
  res.json({ ok: true });
});

app.delete('/api/newspapers/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM newspapers WHERE id=? AND user_id=?').run(req.params.id, req.user.userId);
  res.json({ ok: true });
});

app.get('/api/deliveries', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT date_key, np_id, qty FROM deliveries WHERE user_id = ?').all(req.user.userId);
  const deliveries = {};
  for (const r of rows) {
    if (!deliveries[r.date_key]) deliveries[r.date_key] = {};
    deliveries[r.date_key][r.np_id] = r.qty;
  }
  res.json(deliveries);
});

app.post('/api/deliveries', requireAuth, (req, res) => {
  const { date, npId, qty } = req.body;
  if (!date || !npId) return res.status(400).json({ error: 'date and npId required' });
  if (!qty || qty <= 0) {
    db.prepare('DELETE FROM deliveries WHERE user_id=? AND date_key=? AND np_id=?')
      .run(req.user.userId, date, npId);
  } else {
    db.prepare(`
      INSERT INTO deliveries (user_id, date_key, np_id, qty) VALUES (?, ?, ?, ?)
      ON CONFLICT(user_id, date_key, np_id) DO UPDATE SET qty=excluded.qty
    `).run(req.user.userId, date, npId, qty);
  }
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Newspaper Tracker running at http://localhost:${PORT}`));
