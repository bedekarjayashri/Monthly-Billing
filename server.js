require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'newspaper-tracker-secret-change-in-production';
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/newspaper-tracker';

mongoose.connect(MONGODB_URI).then(() => console.log('Connected to MongoDB'));

const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password_hash: { type: String, required: true }
}));

const Newspaper = mongoose.model('Newspaper', new mongoose.Schema({
  _id: String,
  user_id: { type: String, required: true },
  name: { type: String, required: true },
  prices: { type: String, default: '[]' },
  monthly_delivery_charge: { type: Number, default: 0 }
}));

const deliverySchema = new mongoose.Schema({
  user_id: { type: String, required: true },
  date_key: { type: String, required: true },
  np_id: { type: String, required: true },
  qty: { type: Number, default: 0 }
});
deliverySchema.index({ user_id: 1, date_key: 1, np_id: 1 }, { unique: true });
const Delivery = mongoose.model('Delivery', deliverySchema);

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

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    const existing = await User.findOne({ username });
    if (existing) return res.status(409).json({ error: 'Username already taken' });
    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password_hash: hash });
    const token = jwt.sign({ userId: user._id.toString(), username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = await User.findOne({ username });
    if (!user || !await bcrypt.compare(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const token = jwt.sign({ userId: user._id.toString(), username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

function parsePriceHistory(pricesJson, fallbackCharge) {
  const parsed = JSON.parse(pricesJson);
  if (Array.isArray(parsed)) return parsed;
  return [{ from: '2000-01-01', prices: parsed, monthlyDeliveryCharge: fallbackCharge || 0 }];
}

app.get('/api/newspapers', requireAuth, async (req, res) => {
  try {
    const rows = await Newspaper.find({ user_id: req.user.userId });
    res.json(rows.map(r => ({
      id: r._id,
      name: r.name,
      priceHistory: parsePriceHistory(r.prices, r.monthly_delivery_charge)
    })));
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/newspapers', requireAuth, async (req, res) => {
  try {
    const { id, name, prices, monthlyDeliveryCharge } = req.body;
    if (!id || !name) return res.status(400).json({ error: 'id and name required' });
    const existing = await Newspaper.findOne({ user_id: req.user.userId, name });
    if (existing) return res.status(409).json({ error: 'An item with that name already exists' });
    const priceHistory = [{ from: '2000-01-01', prices: prices || {}, monthlyDeliveryCharge: monthlyDeliveryCharge || 0 }];
    await Newspaper.create({ _id: id, user_id: req.user.userId, name, prices: JSON.stringify(priceHistory), monthly_delivery_charge: monthlyDeliveryCharge || 0 });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.put('/api/newspapers/:id', requireAuth, async (req, res) => {
  try {
    const { name, newRateEntry } = req.body;
    if (!name) return res.status(400).json({ error: 'name required' });
    const conflict = await Newspaper.findOne({ user_id: req.user.userId, name, _id: { $ne: req.params.id } });
    if (conflict) return res.status(409).json({ error: 'An item with that name already exists' });
    const row = await Newspaper.findOne({ _id: req.params.id, user_id: req.user.userId });
    if (!row) return res.status(404).json({ error: 'Not found' });
    let history = parsePriceHistory(row.prices, row.monthly_delivery_charge);
    if (newRateEntry) {
      history = history.filter(e => e.from !== newRateEntry.from);
      history.push(newRateEntry);
      history.sort((a, b) => a.from.localeCompare(b.from));
    }
    const latestCharge = history[history.length - 1]?.monthlyDeliveryCharge || 0;
    await Newspaper.updateOne(
      { _id: req.params.id, user_id: req.user.userId },
      { name, prices: JSON.stringify(history), monthly_delivery_charge: latestCharge }
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/newspapers/:id', requireAuth, async (req, res) => {
  try {
    await Newspaper.deleteOne({ _id: req.params.id, user_id: req.user.userId });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/deliveries', requireAuth, async (req, res) => {
  try {
    const rows = await Delivery.find({ user_id: req.user.userId });
    const deliveries = {};
    for (const r of rows) {
      if (!deliveries[r.date_key]) deliveries[r.date_key] = {};
      deliveries[r.date_key][r.np_id] = r.qty;
    }
    res.json(deliveries);
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/deliveries', requireAuth, async (req, res) => {
  try {
    const { date, npId, qty } = req.body;
    if (!date || !npId) return res.status(400).json({ error: 'date and npId required' });
    if (!qty || qty <= 0) {
      await Delivery.deleteOne({ user_id: req.user.userId, date_key: date, np_id: npId });
    } else {
      await Delivery.findOneAndUpdate(
        { user_id: req.user.userId, date_key: date, np_id: npId },
        { qty },
        { upsert: true }
      );
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => console.log(`Newspaper Tracker running at http://localhost:${PORT}`));
