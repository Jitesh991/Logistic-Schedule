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

// Thrown when the store is unreachable/suspended. Never confuse this with
// "no users exist yet" — that mistake overwrites the real user list with
// a fresh default admin the moment the store recovers.
class StoreUnavailable extends Error {}

// Returns an array of users, or null ONLY when the file genuinely
// does not exist yet (HTTP 404) and it is safe to bootstrap an admin.
async function getUsers() {
  const url = usersUrl();
  if (!url) throw new StoreUnavailable('BLOB_READ_WRITE_TOKEN missing or malformed');

  let res;
  try {
    res = await fetch(`${url}?t=${Date.now()}`, {
      headers: { 'Cache-Control': 'no-cache, no-store' }
    });
  } catch (e) {
    throw new StoreUnavailable(`network error reading users: ${e.message}`);
  }

  if (res.status === 404) return null;   // genuinely not created yet
  if (!res.ok) throw new StoreUnavailable(`status ${res.status} reading users`);

  try {
    const json = await res.json();
    if (!Array.isArray(json)) throw new Error('not an array');
    return json;
  } catch (e) {
    throw new StoreUnavailable(`bad JSON in users file: ${e.message}`);
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
    return res.json({ user: { username: payload.username, name: payload.name, role: payload.role,
                              driverName: payload.driverName || '' } });
  }

  try {
  if (action === 'login') {
    const { username, password } = body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    let users = await getUsers();          // throws if the store is unreachable
    if (users === null) {
      // Genuine first run (404) — safe to seed the default admin
      const admin = makeDefaultAdmin();
      await saveUsers([admin]);
      users = [admin];
    }
    if (!users.length) {
      return res.status(503).json({ error: 'User list is empty — contact your administrator' });
    }

    const user = users.find(u => u.username === username.trim().toLowerCase());
    if (!user || user.passwordHash !== hashPw(password)) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const payload = { id: user.id, username: user.username, name: user.name, role: user.role,
                      driverName: user.driverName || '', exp: Date.now() + TOKEN_TTL };
    return res.json({
      token: signToken(payload),
      user: { username: user.username, name: user.name, role: user.role,
              driverName: user.driverName || '' }
    });
  }

  // ── Everything below is admin-only ──
  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller)                 return res.status(401).json({ error: 'Unauthorized' });
  if (caller.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });

  if (action === 'list-users') {
    const users = await getUsers() || [makeDefaultAdmin()];
    return res.json({ users: users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, driverName: u.driverName || '' })) });
  }

  if (action === 'save-user') {
    const { userId, userUsername, userName, userRole, userPassword } = body;
    if (!userUsername || !userRole || !userName) {
      return res.status(400).json({ error: 'Username, full name, and role are required' });
    }
    const uname = userUsername.trim().toLowerCase();
    // getUsers() throws if the store is unreachable, so we never build a
    // one-element list from a failed read and save it over everyone.
    let users = await getUsers() || [makeDefaultAdmin()];
    const existing = users.find(u => u.id === userId);
    if (existing) {
      if (users.some(u => u.username === uname && u.id !== userId)) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      existing.username = uname;
      existing.name     = userName.trim();
      existing.role     = userRole;
      existing.driverName = userRole === 'driver' ? String(body.driverName || '').trim() : '';
      if (userPassword) existing.passwordHash = hashPw(userPassword);
    } else {
      if (!userPassword) return res.status(400).json({ error: 'Password required for new users' });
      if (users.some(u => u.username === uname)) {
        return res.status(400).json({ error: 'Username already taken' });
      }
      users.push({
        id: crypto.randomBytes(8).toString('hex'),
        username: uname, name: userName.trim(), role: userRole,
        driverName: userRole === 'driver' ? String(body.driverName || '').trim() : '',
        passwordHash: hashPw(userPassword)
      });
    }
    await saveUsers(users);
    return res.json({ ok: true });
  }

  if (action === 'delete-user') {
    const { userId } = body;
    if (userId === caller.id) return res.status(400).json({ error: 'You cannot delete your own account' });
    const current = await getUsers();
    if (!current) return res.status(503).json({ error: 'No user list found — nothing was changed' });
    const users = current.filter(u => u.id !== userId);
    if (!users.some(u => u.role === 'admin')) {
      return res.status(400).json({ error: 'Cannot delete the last admin account' });
    }
    await saveUsers(users);
    return res.json({ ok: true });
  }

  return res.status(400).json({ error: 'Unknown action' });

  } catch (e) {
    const suspended = /suspended/i.test(e.message || '') || /status 403/.test(e.message || '');
    console.error('/api/auth failed:', e.message);
    return res.status(503).json({
      error: suspended
        ? 'Storage is suspended — check Blob usage/billing in your Vercel dashboard. No accounts were changed.'
        : `Storage unavailable: ${e.message}. No accounts were changed.`,
      storeSuspended: suspended
    });
  }
};
