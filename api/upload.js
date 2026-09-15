const crypto = require('crypto');
const { put } = require('@vercel/blob');   // put only — no advanced operations

const SECRET = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';

// Images arrive already resized and JPEG-compressed by the browser. This ceiling
// is a backstop against an uncompressed upload, not the expected size (~180 KB).
const MAX_BYTES = 2 * 1024 * 1024;

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

// Keep the path predictable and safe — it becomes part of a public URL
const clean = s => String(s || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 40);

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });

  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller) return res.status(401).json({ error: 'Unauthorized — please log in again' });
  if (caller.role === 'viewer') return res.status(403).json({ error: 'Read-only access' });

  const { slipId, kind, data } = req.body || {};
  if (!data)   return res.status(400).json({ error: 'data required' });
  if (!slipId) return res.status(400).json({ error: 'slipId required' });

  // Accept "data:image/jpeg;base64,..." or a bare base64 string
  const m = String(data).match(/^data:image\/(jpeg|jpg|png);base64,(.+)$/);
  const b64 = m ? m[2] : String(data);
  const ext = m && m[1] === 'png' ? 'png' : 'jpg';

  let buf;
  try { buf = Buffer.from(b64, 'base64'); }
  catch { return res.status(400).json({ error: 'data is not valid base64' }); }

  if (!buf.length)           return res.status(400).json({ error: 'empty image' });
  if (buf.length > MAX_BYTES) {
    return res.status(413).json({
      error: `Image is ${(buf.length/1024/1024).toFixed(1)} MB — compress it before uploading`
    });
  }

  const name = `${clean(kind) || 'photo'}-${Date.now()}-${crypto.randomBytes(4).toString('hex')}.${ext}`;
  const path = `slips/${clean(slipId)}/${name}`;

  try {
    // 1 simple operation. Photos are immutable once written, so a long cache is
    // safe and keeps repeat views off the origin.
    const blob = await put(path, buf, {
      access: 'public',
      addRandomSuffix: false,
      allowOverwrite: true,
      contentType: ext === 'png' ? 'image/png' : 'image/jpeg',
      cacheControlMaxAge: 31536000
    });
    return res.json({ ok: true, url: blob.url, path, bytes: buf.length });
  } catch (e) {
    console.error('/api/upload failed:', e.message);
    const suspended = /suspended/i.test(e.message || '');
    return res.status(502).json({
      ok: false,
      error: suspended
        ? 'Storage is suspended — check Blob usage in your Vercel dashboard'
        : e.message
    });
  }
};
