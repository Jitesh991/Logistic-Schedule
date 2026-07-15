// api/auth.js — Login, token verify, and user management
// Environment variables required in Vercel dashboard:
//   JWT_SECRET      — any long random string (e.g. openssl rand -hex 32)
//   PASSWORD_SALT   — any long random string (e.g. openssl rand -hex 16)
//   BLOB_READ_WRITE_TOKEN — auto-set when you connect Vercel Blob

const crypto = require('crypto');
const { put, list, del } = require('@vercel/blob');

const SECRET      = process.env.JWT_SECRET     || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const SALT        = process.env.PASSWORD_SALT  || 'sii-salt-CHANGE-IN-PRODUCTION';
const BLOB_PREFIX = 'sii/users.json';
const TOKEN_TTL   = 8 * 60 * 60 * 1000; // 8 hours

// ── Crypto helpers ──────────────────────────────────
function hashPw(pw) {
  return crypto.createHash('sha256').update(SALT + pw + SALT).digest('hex');
}

function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig  = crypto.createHmac('sha256', SECRET).update(data).digest('hex').toUpperCase();
  return data + '.' + sig;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot === -1) return null;
  const data = token.slice(0, dot);
  const sig  = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex').toUpperCase();
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ── Blob helpers ────────────────────────────────────
async function getUsers() {
  try {
    const { blobs } = await list({ prefix: BLOB_PREFIX });
    if (!blobs.length) return null;
    const sorted = blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    const res = await fetch(sorted[0].url);
    return await res.json();
  } catch (e) {
    console.error('getUsers error:', e);
    return null;
  }
}

async function saveUsers(users) {
  const { blobs } = await list({ prefix: BLOB_PREFIX });
  if (blobs.length) await Promise.all(blobs.map(b => del(b.url)));
  await put(BLOB_PREFIX, JSON.stringify(users), {
    access: 'private',
    addRandomSuffix: false,
    contentType: 'application/json'
  });
}

// ── Default admin (first-run) ────────────────────────
function makeDefaultAdmin() {
  return {
    id: 'admin',
    username: 'admin',
    name: 'Administrator',
    role: 'admin',
    passwordHash: hashPw('admin123')
  };
}

// ── Main handler ────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const body     = req.body || {};
  const { action } = body;

  // ── PUBLIC: login ──
  if (action === 'login') {
    const { username, password } = body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    let users = await getUsers();
    if (!users) {
      const admin = makeDefaultAdmin();
      await saveUsers([admin]);
      users = [admin];
    }

    const user = users.find(u => u.username === username.trim().toLowerCase());
    if (!user || user.passwordHash !== hashPw(password)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const payload = { id: user.id, username: user.username, name: user.name, role: user.role, exp: Date.now() + TOKEN_TTL };
    return res.json({ token: signToken(payload), user: { username: user.username, name: user.name, role: user.role } });
  }

  // ── PUBLIC: verify ──
  if (action === 'verify') {
    const payload = verifyToken(body.token);
    if (!payload) return res.status(401).json({ error: 'Invalid or expired session' });
    return res.json({ user: { username: payload.username, name: payload.name, role: payload.role } });
  }

  // ── PROTECTED: require valid token ──
  const rawToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const caller   = verifyToken(rawToken);
  if (!caller)              return res.status(401).json({ error: 'Unauthorized' });
  if (caller.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

  // ── list-users ──
  if (action === 'list-users') {
    const users = await getUsers() || [makeDefaultAdmin()];
    return res.json({ users: users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role })) });
  }

  // ── save-user ──
  if (action === 'save-user') {
    const { userId, userUsername, userName, userRole, userPassword } = body;
    if (!userUsername || !userRole || !userName)
      return res.status(400).json({ error: 'Username, full name, and role are required' });

    let users = await getUsers() || [makeDefaultAdmin()];
    const existing = users.find(u => u.id === userId);

    if (existing) {
      existing.username = userUsername.trim().toLowerCase();
      existing.name     = userName.trim();
      existing.role     = userRole;
      if (userPassword) existing.passwordHash = hashPw(userPassword);
    } else {
      if (!userPassword) return res.status(400).json({ error: 'Password required for new users' });
      if (users.some(u => u.username === userUsername.trim().toLowerCase()))
        return res.status(400).json({ error: 'Username already taken' });
      users.push({
        id:           crypto.randomBytes(8).toString('hex'),
        username:     userUsername.trim().toLowerCase(),
        name:         userName.trim(),
        role:         userRole,
        passwordHash: hashPw(userPassword)
      });
    }
    await saveUsers(users);
    return res.json({ ok: true });
  }

  // ── delete-user ──
  if (action === 'delete-user') {
    const { userId } = body;
    if (userId === caller.id) return res.status(400).json({ error: 'You cannot delete your own account' });
    const users = (await getUsers() || []).filter(u => u.id !== userId);
    await saveUsers(users);
    return res.json({ ok: true });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
