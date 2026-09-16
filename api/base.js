const crypto = require('crypto');

const SECRET   = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const LARK_API = 'https://open.larksuite.com/open-apis';

const APP_TOKEN = process.env.LARK_BASE_APP_TOKEN;   // the Base ("app") token
const TABLE_ID  = process.env.LARK_BASE_TABLE_ID;    // the table inside that Base

// Field names must match the Base exactly — Bitable addresses fields by name
const F = {
  key:      'Sync Key',
  date:     'Date',
  plate:    'Plate',
  driver:   'Driver',
  helpers:  'Helpers',
  stops:    'Stops',
  custs:    'Customers',
  pos:      'Total POs',
  time:     'First Stop Time',
  pullout:  'Has Pullout',
  permits:  'Permits',
  notes:    'Notes',
  updated:  'Updated At'
};

// ── Auth (same HMAC scheme as the other endpoints) ───────────────────────────
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

// Token cache lives per warm instance; deliberately duplicated from api/lark.js
// so that file keeps working untouched.
let _tok = { value: null, exp: 0 };

async function tenantToken() {
  if (_tok.value && Date.now() < _tok.exp) return _tok.value;
  const appId = process.env.LARK_APP_ID, appSecret = process.env.LARK_APP_SECRET;
  if (!appId || !appSecret) throw new Error('LARK_APP_ID / LARK_APP_SECRET not configured');

  const res  = await fetch(`${LARK_API}/auth/v3/tenant_access_token/internal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: appId, app_secret: appSecret })
  });
  const json = await res.json();
  if (json.code !== 0) throw new Error(`Lark token failed (${json.code}): ${json.msg}`);
  _tok = { value: json.tenant_access_token,
           exp: Date.now() + Math.max(60, (json.expire || 7200) - 60) * 1000 };
  return _tok.value;
}

async function bitable(path, opts = {}) {
  const token = await tenantToken();
  const res = await fetch(`${LARK_API}/bitable/v1/apps/${APP_TOKEN}/tables/${TABLE_ID}${path}`, {
    ...opts,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json; charset=utf-8',
      ...(opts.headers || {})
    }
  });
  const json = await res.json().catch(() => ({}));
  if (json.code !== 0) {
    const hint = json.code === 91403 || json.code === 1254302
      ? ' — the app is probably not a collaborator on this Base'
      : '';
    throw new Error(`Bitable ${json.code}: ${json.msg || res.status}${hint}`);
  }
  return json.data;
}

// Find an existing row by its sync key. Returns record_id or null.
async function findRecord(syncKey) {
  const data = await bitable('/records/search?page_size=1', {
    method: 'POST',
    body: JSON.stringify({
      filter: {
        conjunction: 'and',
        conditions: [{ field_name: F.key, operator: 'is', value: [String(syncKey)] }]
      },
      automatic_fields: false
    })
  });
  return data.items && data.items.length ? data.items[0].record_id : null;
}

// Date fields take epoch milliseconds.
// Anchored to midday Manila, not midnight: at midnight a Base configured for any
// timezone behind PH renders the previous day, which would put the wrong date on
// a driver slip. Midday leaves ~12 hours of slack in both directions.
function toEpoch(dateStr) {
  if (!dateStr) return null;
  const d = new Date(`${dateStr}T12:00:00+08:00`);
  return isNaN(d) ? null : d.getTime();
}

function buildFields(row) {
  const fields = {
    [F.key]:     String(row.syncKey || ''),
    [F.plate]:   String(row.plate || ''),
    [F.driver]:  String(row.driver || ''),
    [F.helpers]: String(row.helpers || ''),
    [F.stops]:   String(row.stops || ''),
    [F.custs]:   String(row.customers || ''),
    [F.pos]:     Number(row.totalPos || 0),
    [F.time]:    String(row.firstTime || ''),
    [F.pullout]: Boolean(row.pullout),
    [F.permits]: String(row.permits || ''),
    [F.notes]:   String(row.notes || ''),
    [F.updated]: Date.now()
  };
  const dt = toEpoch(row.date);
  if (dt) fields[F.date] = dt;
  return fields;
}

// ── Handler ──────────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });

  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller) return res.status(401).json({ error: 'Unauthorized — please log in again' });
  if (caller.role === 'viewer') return res.status(403).json({ error: 'Read-only access' });

  // Not configured yet? Say so plainly instead of erroring — the schedule save
  // itself already succeeded, and this must never look like data loss.
  if (!APP_TOKEN || !TABLE_ID) {
    return res.json({ ok: false, disabled: true,
      error: 'Base sync is off — set LARK_BASE_APP_TOKEN and LARK_BASE_TABLE_ID in Vercel' });
  }

  const { op, row, syncKey, rows } = req.body || {};

  try {
    if (op === 'diagnose') {
      const data = await bitable('/records/search?page_size=1', {
        method: 'POST', body: JSON.stringify({ automatic_fields: false })
      });
      // Report which expected fields are actually present on a sample row
      const seen = data.items && data.items[0] ? Object.keys(data.items[0].fields || {}) : [];
      const expected = Object.values(F);
      return res.json({
        ok: true, reachable: true, sampleRows: (data.items || []).length,
        fieldsSeen: seen,
        missing: seen.length ? expected.filter(f => !seen.includes(f)) : null
      });
    }

    if (op === 'delete') {
      if (!syncKey) return res.status(400).json({ error: 'syncKey required' });
      const id = await findRecord(syncKey);
      if (!id) return res.json({ ok: true, deleted: false });   // nothing there — fine
      await bitable(`/records/${id}`, { method: 'DELETE' });
      return res.json({ ok: true, deleted: true });
    }

    // upsert one row, or several in one call
    const list = Array.isArray(rows) ? rows : (row ? [row] : []);
    if (!list.length) return res.status(400).json({ error: 'row or rows required' });

    let created = 0, updated = 0;
    for (const r of list) {
      if (!r || !r.syncKey) continue;
      const fields = buildFields(r);
      const id = await findRecord(r.syncKey);
      if (id) {
        await bitable(`/records/${id}`, { method: 'PUT', body: JSON.stringify({ fields }) });
        updated++;
      } else {
        await bitable('/records', { method: 'POST', body: JSON.stringify({ fields }) });
        created++;
      }
    }
    return res.json({ ok: true, created, updated });

  } catch (e) {
    console.error('/api/base failed:', e.message);
    return res.status(502).json({ ok: false, error: e.message });
  }
};
