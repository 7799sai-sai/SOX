'use strict';
const express  = require('express');
const Database = require('better-sqlite3');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

try { require('dotenv').config(); } catch(e) { /* env vars set directly on Render */ }

const app    = express();
const PORT   = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'keystone-dev-secret-CHANGE-IN-PRODUCTION';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'keystone.db');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// ── middleware ──────────────────────────────────────────────────────────────
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: '16mb' })); // workspace JSON can be several MB

// ── database ─────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT   NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS workspaces (
    user_id    INTEGER PRIMARY KEY,
    state_json TEXT    NOT NULL,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed token' });
  }
  try {
    req.user = jwt.verify(header.slice(7), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalid or expired — please sign in again' });
  }
}

function makeToken(userId, email) {
  return jwt.sign({ userId, email }, SECRET, { expiresIn: '30d' });
}

// ── routes ───────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// Register
app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  const emailClean = email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  try {
    const hash = bcrypt.hashSync(password, 10);
    const { lastInsertRowid } = db
      .prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
      .run(emailClean, hash);
    res.status(201).json({ token: makeToken(lastInsertRowid, emailClean), email: emailClean });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'This email is already registered — try signing in' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed — please try again' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  res.json({ token: makeToken(user.id, user.email), email: user.email });
});

// Get workspace state for the authenticated user
app.get('/api/workspace', requireAuth, (req, res) => {
  const row = db
    .prepare('SELECT state_json, updated_at FROM workspaces WHERE user_id = ?')
    .get(req.user.userId);
  if (!row) return res.json({ state: null });
  try {
    res.json({ state: JSON.parse(row.state_json), updated_at: row.updated_at });
  } catch {
    res.json({ state: null });
  }
});

// Save (upsert) workspace state for the authenticated user
app.put('/api/workspace', requireAuth, (req, res) => {
  const { state } = req.body || {};
  if (!state || typeof state !== 'object') {
    return res.status(400).json({ error: 'A valid state object is required' });
  }
  try {
    db.prepare(`
      INSERT INTO workspaces (user_id, state_json, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
    `).run(req.user.userId, JSON.stringify(state));
    res.json({ ok: true });
  } catch (err) {
    console.error('Workspace save error:', err);
    res.status(500).json({ error: 'Could not save workspace' });
  }
});

// Delete workspace (reset) for the authenticated user
app.delete('/api/workspace', requireAuth, (req, res) => {
  db.prepare('DELETE FROM workspaces WHERE user_id = ?').run(req.user.userId);
  res.json({ ok: true });
});

// ── start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Keystone SOX backend listening on port ${PORT}`);
  console.log(`CORS origin: ${CORS_ORIGIN}`);
  console.log(`Database:    ${DB_PATH}`);
});
