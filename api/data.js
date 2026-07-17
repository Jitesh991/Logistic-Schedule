const crypto = require('crypto');
const { put, del } = require('@vercel/blob');   // list/head no longer needed

const SECRET     = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const VALID_COLS = ['schedules', 'trucks', 'customers', 'drivers', 'holidays'];

// ── Derive the public blob store base URL from the token ──────────────────────
// Token format: vercel_blob_rw_{storeId}_{secret}
// This lets us build the deterministic public URL without any list()/head() calls.
function blobBaseUrl() {
  const token = process.env.BLOB_READ_WRITE_TOKEN || '';
  const parts = token.split('_');
  // parts: ['vercel','blob','rw','{storeId}','{secret}']
  if (parts.length >= 4) {
    return `https://${parts[3]}.public.blob.vercel-storage.com`;
  }
  return null;
}

function colUrl(col) {
  const base = blobBaseUrl();
  if (!base) return null;
  return `${base}/sii/${col}.json`;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
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

// ── Read: direct public fetch — 0 advanced operations ────────────────────────
async function readCol(col) {
  try {
    const url = colUrl(col);
    if (url) {
      // Public blob — no auth needed, no list()/head() needed
      const res = await fetch(`${url}?t=${Date.now()}`, {
        headers: { 'Cache-Control': 'no-cache, no-store' }
      });
      if (res.ok)             return await res.json();
      if (res.status === 404) return [];   // collection doesn't exist yet — fine
      // unexpected status: fall through to legacy path
    }
    // Fallback (only if token parsing fails / local dev without env var)
    const { list } = require('@vercel/blob');
    const { blobs } = await list({ prefix: `sii/${col}.json` });
    if (!blobs.length) return [];
    const sorted = blobs.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    const r = await fetch(sorted[0].url);
    return r.ok ? await r.json() : [];
  } catch (e) {
    console.error(`readCol(${col}) error:`, e);
    return [];
  }
}

// ── Write: delete by known URL + put — 1 advanced op (del) + 1 simple op (put)
async function writeCol(col, data) {
  const url = colUrl(col);
  if (url) {
    // Delete the known URL directly — no list() needed
    try { await del(url); } catch { /* 404 is fine on first write */ }
  } else {
    // Fallback
    const { list } = require('@vercel/blob');
    const { blobs } = await list({ prefix: `sii/${col}.json` });
    if (blobs.length) await Promise.all(blobs.map(b => del(b.url)));
  }
  await put(`sii/${col}.json`, JSON.stringify(data), {
    addRandomSuffix: false,
    access: 'public',
    contentType: 'application/json'
  });
}

// ── Handler ───────────────────────────────────────────────────────────────────
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
