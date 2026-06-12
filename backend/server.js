'use strict';
const express   = require('express');
const Database  = require('better-sqlite3');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const path      = require('path');

try { require('dotenv').config(); } catch(e) { /* env vars set directly on Render */ }

const app         = express();
const PORT        = process.env.PORT        || 3001;
const SECRET      = process.env.JWT_SECRET  || 'keystone-dev-secret-CHANGE-IN-PRODUCTION';
const DB_PATH     = process.env.DB_PATH     || path.join(__dirname, 'keystone.db');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// ── security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false  // frontend is on a different origin
}));

// ── CORS ─────────────────────────────────────────────────────────────────────
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

// ── body parser ───────────────────────────────────────────────────────────────
app.use(express.json({ limit: '16mb' }));

// ── rate limiters ─────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 10,                    // max 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts — please wait 15 minutes before trying again.' }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,        // 1 minute
  max: 120,                   // 120 req/min per IP (generous for active users)
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests — please slow down.' }
});

app.use('/api/login',    authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/',         apiLimiter);

// ── database ──────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
  );

  CREATE TABLE IF NOT EXISTS workspaces (
    user_id    INTEGER PRIMARY KEY,
    state_json TEXT    NOT NULL,
    updated_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS workspace_snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    state_json TEXT    NOT NULL,
    saved_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    token_hash TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ── helpers ───────────────────────────────────────────────────────────────────
function makeAccessToken(userId, email) {
  return jwt.sign({ userId, email, type: 'access' }, SECRET, { expiresIn: '7d' });
}

function makeRefreshToken(userId, email) {
  return jwt.sign({ userId, email, type: 'refresh' }, SECRET, { expiresIn: '30d' });
}

function storeRefreshToken(userId, token) {
  const payload = jwt.decode(token);
  const expiresAt = new Date(payload.exp * 1000).toISOString();
  const hash = Buffer.from(token).toString('base64').slice(-32); // simple fingerprint
  db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)
  `).run(userId, hash, expiresAt);
  // keep at most 5 refresh tokens per user (prune oldest)
  db.prepare(`
    DELETE FROM refresh_tokens WHERE user_id = ? AND id NOT IN (
      SELECT id FROM refresh_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 5
    )
  `).run(userId, userId);
}

function saveSnapshot(userId, stateJson) {
  db.prepare(`
    INSERT INTO workspace_snapshots (user_id, state_json) VALUES (?, ?)
  `).run(userId, stateJson);
  // keep only the latest 5 snapshots per user
  db.prepare(`
    DELETE FROM workspace_snapshots WHERE user_id = ? AND id NOT IN (
      SELECT id FROM workspace_snapshots WHERE user_id = ? ORDER BY id DESC LIMIT 5
    )
  `).run(userId, userId);
}

function validateEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// ── auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed token' });
  }
  try {
    const payload = jwt.verify(header.slice(7), SECRET);
    if (payload.type !== 'access') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    req.user = payload;
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError'
      ? 'Session expired — please sign in again'
      : 'Token invalid — please sign in again';
    res.status(401).json({ error: msg, expired: err.name === 'TokenExpiredError' });
  }
}

// ── routes ────────────────────────────────────────────────────────────────────

// Health check
app.get('/api/health', (_req, res) => res.json({
  ok: true,
  ts: new Date().toISOString(),
  version: '2.0.0'
}));

// Register
app.post('/api/register', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (password.length > 128) {
    return res.status(400).json({ error: 'Password too long' });
  }
  const emailClean = email.trim().toLowerCase();
  try {
    const hash = bcrypt.hashSync(password, 12); // cost 12 for better resistance
    const { lastInsertRowid } = db
      .prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
      .run(emailClean, hash);
    const accessToken  = makeAccessToken(lastInsertRowid, emailClean);
    const refreshToken = makeRefreshToken(lastInsertRowid, emailClean);
    storeRefreshToken(lastInsertRowid, refreshToken);
    res.status(201).json({ token: accessToken, refreshToken, email: emailClean });
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
  const emailClean = (email || '').trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(emailClean);
  if (!user || !bcrypt.compareSync(String(password).slice(0, 128), user.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  // update last login
  db.prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?").run(user.id);
  const accessToken  = makeAccessToken(user.id, user.email);
  const refreshToken = makeRefreshToken(user.id, user.email);
  storeRefreshToken(user.id, refreshToken);
  res.json({ token: accessToken, refreshToken, email: user.email });
});

// Refresh access token (silent re-auth)
app.post('/api/refresh', (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }
  try {
    const payload = jwt.verify(refreshToken, SECRET);
    if (payload.type !== 'refresh') {
      return res.status(401).json({ error: 'Invalid token type' });
    }
    const user = db.prepare('SELECT id, email FROM users WHERE id = ?').get(payload.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    const newAccessToken  = makeAccessToken(user.id, user.email);
    const newRefreshToken = makeRefreshToken(user.id, user.email);
    storeRefreshToken(user.id, newRefreshToken);
    res.json({ token: newAccessToken, refreshToken: newRefreshToken, email: user.email });
  } catch (err) {
    const msg = err.name === 'TokenExpiredError'
      ? 'Refresh token expired — please sign in again'
      : 'Invalid refresh token';
    res.status(401).json({ error: msg });
  }
});

// Change password
app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required' });
  }
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.userId);
  if (!user || !bcrypt.compareSync(String(currentPassword).slice(0, 128), user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 12);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  // invalidate all refresh tokens on password change
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(user.id);
  res.json({ ok: true });
});

// Get workspace state
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

// Save (upsert) workspace state + auto-snapshot
app.put('/api/workspace', requireAuth, (req, res) => {
  const { state } = req.body || {};
  if (!state || typeof state !== 'object') {
    return res.status(400).json({ error: 'A valid state object is required' });
  }
  try {
    const json = JSON.stringify(state);
    // save snapshot before overwriting (Phase 2 — versioning)
    const existing = db
      .prepare('SELECT state_json FROM workspaces WHERE user_id = ?')
      .get(req.user.userId);
    if (existing) saveSnapshot(req.user.userId, existing.state_json);

    db.prepare(`
      INSERT INTO workspaces (user_id, state_json, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
    `).run(req.user.userId, json);
    res.json({ ok: true });
  } catch (err) {
    console.error('Workspace save error:', err);
    res.status(500).json({ error: 'Could not save workspace' });
  }
});

// List workspace snapshots (Phase 2)
app.get('/api/workspace/snapshots', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, saved_at FROM workspace_snapshots
    WHERE user_id = ? ORDER BY id DESC LIMIT 5
  `).all(req.user.userId);
  res.json({ snapshots: rows });
});

// Restore a specific snapshot (Phase 2)
app.post('/api/workspace/snapshots/:id/restore', requireAuth, (req, res) => {
  const snap = db.prepare(`
    SELECT state_json FROM workspace_snapshots WHERE id = ? AND user_id = ?
  `).get(req.params.id, req.user.userId);
  if (!snap) return res.status(404).json({ error: 'Snapshot not found' });
  try {
    db.prepare(`
      INSERT INTO workspaces (user_id, state_json, updated_at)
      VALUES (?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
    `).run(req.user.userId, snap.state_json);
    res.json({ ok: true, state: JSON.parse(snap.state_json) });
  } catch (err) {
    res.status(500).json({ error: 'Could not restore snapshot' });
  }
});

// Delete workspace (reset)
app.delete('/api/workspace', requireAuth, (req, res) => {
  db.prepare('DELETE FROM workspaces WHERE user_id = ?').run(req.user.userId);
  res.json({ ok: true });
});

// ── 404 catch-all ─────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ── start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Keystone SOX backend v2 listening on port ${PORT}`);
  console.log(`CORS origin: ${CORS_ORIGIN}`);
  console.log(`Database:    ${DB_PATH}`);
});
