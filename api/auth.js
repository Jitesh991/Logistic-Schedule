const crypto = require('crypto');
const { put } = require('@vercel/blob');   // put only — no list/del/head/copy

const SECRET    = process.env.JWT_SECRET    || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const SALT      = process.env.PASSWORD_SALT || 'sii-salt-CHANGE-IN-PRODUCTION';
const BLOB_PATH = 'sii/users.json';
const TOKEN_TTL = 8 * 60 * 60 * 1000;

// ── Tokens ───────────────────────────────────────────────────────────────────
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
  const data = token.slice(0, dot), sig = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SECRET).update(data).digest('hex').toUpperCase();
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  USER STORE — zero advanced operations
//
//  Was: list() to find the blob + head() to resolve it  = 2 advanced ops
//       per getUsers(), and list()+del() per saveUsers() = 2 more.
//  Now: the public URL is derived from the token, and put() overwrites
//       in place. Reads cost nothing; writes cost 1 simple op.
// ─────────────────────────────────────────────────────────────────────────────
function usersUrl() {
  const parts = (process.env.BLOB_READ_WRITE_TOKEN || '').split('_');
  if (parts.length < 4) return null;
  return `https://${parts[3]}.public.blob.vercel-storage.com/${BLOB_PATH}`;
}

async function getUsers() {
  const url = usersUrl();
  if (!url) { console.error('BLOB_READ_WRITE_TOKEN missing or malformed'); return null; }
  try {
    const res = await fetch(`${url}?t=${Date.now()}`, {
      headers: { 'Cache-Control': 'no-cache, no-store' }
    });
    if (res.status === 404) return null;        // no users file yet
    if (!res.ok) { console.error(`getUsers status ${res.status}`); return null; }
    return await res.json();
  } catch (e) {
    console.error('getUsers error:', e);
    return null;
  }
}

async function saveUsers(users) {
  await put(BLOB_PATH, JSON.stringify(users), {
    access: 'public',
    addRandomSuffix: false,
    allowOverwrite: true,
    contentType: 'application/json',
    cacheControlMaxAge: 0
  });
}

function makeDefaultAdmin() {
  return { id: 'admin', username: 'admin', name: 'Administrator', role: 'admin', passwordHash: hashPw('admin123') };
}

// ── Handler ──────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });

  const body = req.body || {};
  const { action } = body;

  // verify — pure HMAC, touches no storage at all
  if (action === 'verify') {
    const payload = verifyToken(body.token);
    if (!payload) return res.status(401).json({ error: 'Invalid or expired session' });
    return res.json({ user: { username: payload.username, name: payload.name, role: payload.role } });
  }

  if (action === 'login') {
    const { username, password } = body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    let users = await getUsers();
    if (!users || !users.length) {
      const admin = makeDefaultAdmin();
      await saveUsers([admin]);
      users = [admin];
    }
    const user = users.find(u => u.username === username.trim().toLowerCase());
    if (!user || user.passwordHash !== hashPw(password)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const payload = { id: user.id, username: user.username, name: user.name, role: user.role, exp: Date.now() + TOKEN_TTL };
    return res.json({
      token: signToken(payload),
      user: { username: user.username, name: user.name, role: user.role }
    });
  }

  // ── Everything below is admin-only ──
  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller)                 return res.status(401).json({ error: 'Unauthorized' });
  if (caller.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

  if (action === 'list-users') {
    const users = await getUsers() || [makeDefaultAdmin()];
    return res.json({ users: users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role })) });
  }

  if (action === 'save-user') {
    const { userId, userUsername, userName, userRole, userPassword } = body;
    if (!userUsername || !userRole || !userName) {
      return res.status(400).json({ error: 'Username, full name, and role are required' });
    }
    const uname = userUsername.trim().toLowerCase();
    let users = await getUsers() || [makeDefaultAdmin()];
    const existing = users.find(u => u.id === userId);
    if (existing) {
      if (users.some(u => u.username === uname && u.id !== userId)) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      existing.username = uname;
      existing.name     = userName.trim();
      existing.role     = userRole;
      if (userPassword) existing.passwordHash = hashPw(userPassword);
    } else {
      if (!userPassword) return res.status(400).json({ error: 'Password required for new users' });
      if (users.some(u => u.username === uname)) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      users.push({
        id: crypto.randomBytes(8).toString('hex'),
        username: uname, name: userName.trim(), role: userRole,
        passwordHash: hashPw(userPassword)
      });
    }
    await saveUsers(users);
    return res.json({ ok: true });
  }

  if (action === 'delete-user') {
    const { userId } = body;
    if (userId === caller.id) return res.status(400).json({ error: 'You cannot delete your own account' });
    const users = (await getUsers() || []).filter(u => u.id !== userId);
    if (!users.some(u => u.role === 'admin')) {
      return res.status(400).json({ error: 'Cannot delete the last admin account' });
    }
    await saveUsers(users);
    return res.json({ ok: true });
  }

  return res.status(400).json({ error: 'Unknown action' });
};
