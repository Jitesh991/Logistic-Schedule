const crypto = require('crypto');
const { put, list, del, head } = require('@vercel/blob');

const SECRET     = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const VALID_COLS = ['schedules', 'trucks', 'customers', 'drivers'];

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

async function readBlob(url) {
  try {
    const meta = await head(url);
    const res  = await fetch(meta.downloadUrl || url);
    if (!res.ok) return null;
    return await res.text();
  } catch {
    try {
      const res = await fetch(url);
      return res.ok ? await res.text() : null;
    } catch { return null; }
  }
}

async function readCol(col) {
  try {
    const { blobs } = await list({ prefix: `sii/${col}.json` });
    if (!blobs.length) return [];
    const sorted = blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    const text = await readBlob(sorted[0].url);
    return text ? JSON.parse(text) : [];
  } catch (e) { console.error(`readCol(${col}) error:`, e); return []; }
}

async function writeCol(col, data) {
  const { blobs } = await list({ prefix: `sii/${col}.json` });
  if (blobs.length) await Promise.all(blobs.map(b => del(b.url)));
  await put(`sii/${col}.json`, JSON.stringify(data), {
    addRandomSuffix: false,
    access: 'public',
    contentType: 'application/json'
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const rawToken = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const caller   = verifyToken(rawToken);
  if (!caller) return res.status(401).json({ error: 'Unauthorized — please log in again' });

  const col = req.query.col;
  if (!VALID_COLS.includes(col)) return res.status(400).json({ error: `Invalid collection: ${col}` });

  if (req.method === 'GET') {
    const data = await readCol(col);
    return res.json({ data });
  }

  if (req.method === 'POST') {
    if (caller.role === 'viewer') return res.status(403).json({ error: 'Read-only access' });
    const { op, item, id } = req.body || {};

    if (op === 'save') {
      if (!item || !item.id) return res.status(400).json({ error: 'Item with id required' });
      let data = await readCol(col);
      const idx = data.findIndex(x => x.id === item.id);
      if (idx > -1) data[idx] = item; else data.push(item);
      await writeCol(col, data);
      return res.json({ ok: true, data });
    }

    if (op === 'delete') {
      if (!id) return res.status(400).json({ error: 'id required' });
      let data = (await readCol(col)).filter(x => x.id !== id);
      await writeCol(col, data);
      return res.json({ ok: true, data });
    }

    return res.status(400).json({ error: `Unknown op: ${op}` });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
