const crypto = require('crypto');
const { put } = require('@vercel/blob');   // put only — no list/del/head/copy

const SECRET     = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const VALID_COLS = ['schedules', 'trucks', 'customers', 'drivers', 'holidays', 'fuel_soa', 'rfid_soa'];

// Purchase orders and driver slips are sharded by month (po_2026_09,
// slips_2026_09) so a single save never has to rewrite a year of records.
// Keeps every write small and well under Vercel's 4.5 MB request body limit.
// Photos are never stored here — they are separate blobs, see /api/upload.
const SHARDED_COL = /^(po|slips|counter)_\d{4}_(0[1-9]|1[0-2])$/;

function isValidCol(col) {
  return VALID_COLS.includes(col) || SHARDED_COL.test(col || '');
}

// ─────────────────────────────────────────────────────────────────────────────
//  BLOB ACCESS — zero advanced operations
//
//  Reads : plain HTTPS GET of the public blob URL (not a billed blob op).
//  Writes: put() with allowOverwrite, which replaces the object in place.
//          This is a *simple* operation. The old code called del() first,
//          which was an *advanced* operation on every single save.
//
//  The public URL is derived from the token, so we never need list() or head()
//  to discover it. Token format: vercel_blob_rw_{storeId}_{secret}
// ─────────────────────────────────────────────────────────────────────────────
function colUrl(col) {
  const parts = (process.env.BLOB_READ_WRITE_TOKEN || '').split('_');
  if (parts.length < 4) return null;
  return `https://${parts[3]}.public.blob.vercel-storage.com/sii/${col}.json`;
}

// Thrown when the store is unreachable/suspended. Callers MUST NOT treat this
// as "empty collection" — doing so would overwrite good data with nothing.
class StoreUnavailable extends Error {}

async function readCol(col) {
  const url = colUrl(col);
  if (!url) throw new StoreUnavailable('BLOB_READ_WRITE_TOKEN missing or malformed');

  let res;
  try {
    // Cache-bust so edits by one user are seen immediately by others
    res = await fetch(`${url}?t=${Date.now()}`, {
      headers: { 'Cache-Control': 'no-cache, no-store' }
    });
  } catch (e) {
    throw new StoreUnavailable(`network error reading ${col}: ${e.message}`);
  }

  if (res.ok) {
    try {
      const json = await res.json();
      if (!Array.isArray(json)) throw new Error('not an array');
      return json;
    } catch (e) {
      // Corrupt/partial body — refuse rather than risk clobbering
      throw new StoreUnavailable(`bad JSON in ${col}: ${e.message}`);
    }
  }

  // 404 is the ONLY status that legitimately means "nothing stored yet"
  if (res.status === 404) return [];

  // 403 = store suspended or token revoked. Anything else is unexpected.
  throw new StoreUnavailable(`status ${res.status} reading ${col}`);
}

async function writeCol(col, data) {
  await put(`sii/${col}.json`, JSON.stringify(data), {
    access: 'public',
    addRandomSuffix: false,
    allowOverwrite: true,       // replaces in place — no del() needed
    contentType: 'application/json',
    cacheControlMaxAge: 0       // don't let the CDN serve stale data
  });
}

// ── Auth ─────────────────────────────────────────────────────────────────────
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

// ── Handler ──────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller) return res.status(401).json({ error: 'Unauthorized — please log in again' });

  const col = req.query.col;
  if (!isValidCol(col)) return res.status(400).json({ error: `Invalid collection: ${col}` });

  try {
    if (req.method === 'GET') {
      return res.json({ data: await readCol(col) });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
    if (caller.role === 'viewer') return res.status(403).json({ error: 'Read-only access' });

    const { op, item, items, id, ids } = req.body || {};

    // Each branch reads first, then performs exactly one write.
    // If the read throws StoreUnavailable we never reach writeCol, so a
    // failed read can never blank out an existing collection.
    switch (op) {
      case 'save': {
        if (!item || !item.id) return res.status(400).json({ error: 'Item with id required' });
        const data = await readCol(col);
        const idx  = data.findIndex(x => x.id === item.id);
        if (idx > -1) data[idx] = item; else data.push(item);
        await writeCol(col, data);
        return res.json({ ok: true, data });
      }

      case 'saveMany': {
        if (!Array.isArray(items)) return res.status(400).json({ error: 'items array required' });
        const byId = new Map((await readCol(col)).map(x => [x.id, x]));
        for (const it of items) if (it && it.id) byId.set(it.id, it);
        const data = [...byId.values()];
        await writeCol(col, data);
        return res.json({ ok: true, data, saved: items.length });
      }

      case 'delete': {
        if (!id) return res.status(400).json({ error: 'id required' });
        const data = (await readCol(col)).filter(x => x.id !== id);
        await writeCol(col, data);
        return res.json({ ok: true, data });
      }

      case 'deleteMany': {
        if (!Array.isArray(ids)) return res.status(400).json({ error: 'ids array required' });
        const drop = new Set(ids);
        const data = (await readCol(col)).filter(x => !drop.has(x.id));
        await writeCol(col, data);
        return res.json({ ok: true, data });
      }

      // Deliberate wipe — the only op that writes without reading first
      case 'clear': {
        await writeCol(col, []);
        return res.json({ ok: true, data: [] });
      }

      default:
        return res.status(400).json({ error: `Unknown op: ${op}` });
    }
  } catch (e) {
    const suspended = /suspended/i.test(e.message || '') || /status 403/.test(e.message || '');
    console.error(`/api/data ${col} failed:`, e.message);
    return res.status(503).json({
      error: suspended
        ? 'Storage is suspended — check Blob usage/billing in your Vercel dashboard. No data was changed.'
        : `Storage unavailable: ${e.message}. No data was changed.`,
      storeSuspended: suspended
    });
  }
};
