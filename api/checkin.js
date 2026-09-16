const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';

// Trip check-ins go to their own chat if you set one, otherwise the drivers chat
const HOOK = process.env.LARK_HOOK_TRIPS || process.env.LARK_HOOK_DRIVERS;

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

// Turn coordinates into a street address. Best-effort: if the lookup is slow or
// down we still post the check-in with coordinates, because the timestamp and
// the map link are the parts that actually matter.
async function reverseGeocode(lat, lng) {
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat=${lat}&lon=${lng}&zoom=18&addressdetails=1`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { 'User-Agent': 'SII-Logistics/1.0 (operations@sunbeamsimpexinc.com)' }
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const json = await res.json();
    return json.display_name || null;
  } catch {
    return null;
  }
}

const md   = c => ({ tag:'div', text:{ tag:'lark_md', content:c } });
const two  = (a,b) => ({ tag:'div', fields:[
                 { is_short:true, text:{ tag:'lark_md', content:a } },
                 { is_short:true, text:{ tag:'lark_md', content:b } } ] });
const esc  = s => String(s||'').replace(/([*_`~])/g,'\\$1');

async function postHook(payload) {
  const res  = await fetch(HOOK, {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify(payload)
  });
  const json = await res.json().catch(() => ({}));
  const ok = json.code === 0 || json.StatusCode === 0 || res.ok;
  if (!ok) throw new Error(json.msg || json.StatusMessage || `HTTP ${res.status}`);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')    return res.status(405).json({ error: 'Method not allowed' });

  const caller = verifyToken((req.headers.authorization || '').replace(/^Bearer\s+/i, ''));
  if (!caller) return res.status(401).json({ error: 'Unauthorized — please log in again' });

  if (!HOOK) {
    return res.json({ ok:false, disabled:true,
      error:'No trips chat configured — set LARK_HOOK_TRIPS in Vercel' });
  }

  const {
    event, customer, plate, driver, helpers,
    lat, lng, accuracy, at,
    qty, receivingPerson, remarks, photos
  } = req.body || {};

  if (!['in','out'].includes(event)) return res.status(400).json({ error: "event must be 'in' or 'out'" });

  const arriving = event === 'in';
  const when = at ? new Date(at) : new Date();
  const dateStr = when.toLocaleDateString('en-PH', { timeZone:'Asia/Manila', month:'2-digit', day:'2-digit', year:'numeric' });
  const timeStr = when.toLocaleTimeString('en-PH', { timeZone:'Asia/Manila', hour:'2-digit', minute:'2-digit', hour12:true });

  const hasFix = Number.isFinite(Number(lat)) && Number.isFinite(Number(lng));
  const address = hasFix ? await reverseGeocode(lat, lng) : null;
  const mapUrl  = hasFix ? `https://www.google.com/maps/search/?api=1&query=${lat},${lng}` : null;

  const el = [
    md(`**${esc(customer || 'Stop')} — ${arriving ? 'Arrived' : 'Departed'}**`),
    two(`**Date**\n${dateStr}`, `**Time**\n${timeStr}`),
    { tag:'hr' },
    md(`**Detected location**\n${address ? esc(address)
        : hasFix ? `${lat}, ${lng}` : '_Location unavailable — driver declined or no GPS fix_'}`),
    two(`**Truck**\n\`${esc(plate || '—')}\``, `**Driver**\n${esc(driver || '—')}`)
  ];

  if (helpers) el.push(md(`**Helper**\n${esc(helpers)}`));

  el.push(two(
    `**GPS accuracy**\n${hasFix && accuracy ? `±${Math.round(accuracy)} meters` : '—'}`,
    `**Location method**\n${hasFix ? 'Live GPS' : 'Not captured'}`
  ));

  if (!arriving) {
    el.push({ tag:'hr' });
    el.push(two(`**Received by**\n${esc(receivingPerson || '—')}`, `**Qty**\n${esc(String(qty ?? '—'))}`));
    if (remarks) el.push(md(`**Remarks**\n${esc(remarks)}`));
    if (photos)  el.push(md(`📷 ${photos} photo${photos !== 1 ? 's' : ''} attached in the slip`));
  }

  if (mapUrl) {
    el.push({ tag:'action', actions:[{
      tag:'button', text:{ tag:'plain_text', content:'View Location' }, type:'primary', url: mapUrl
    }]});
  }

  el.push({ tag:'note', elements:[{ tag:'plain_text', content:'Saved to SII Logistics driver slip.' }] });

  try {
    await postHook({
      msg_type:'interactive',
      card: {
        config: { wide_screen_mode:true },
        header: {
          template: arriving ? 'blue' : 'green',
          title: { tag:'plain_text',
                   content: `${customer || 'Stop'} — ${arriving ? 'Sign in' : 'Sign out'}` }
        },
        elements: el
      }
    });
    return res.json({ ok:true, address, mapUrl });
  } catch (e) {
    console.error('/api/checkin failed:', e.message);
    return res.status(502).json({ ok:false, error:e.message });
  }
};
