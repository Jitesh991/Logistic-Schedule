const crypto = require('crypto');

const SECRET = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';

// Trip check-ins go to their own chat if you set one, otherwise the drivers chat
const HOOK = process.env.LARK_HOOK_TRIPS || process.env.LARK_HOOK_DRIVERS;
const LARK_API = 'https://open.larksuite.com/open-apis';

// Token cache per warm instance
let _tok = { value:null, exp:0 };
async function tenantToken() {
  if (_tok.value && Date.now() < _tok.exp) return _tok.value;
  const appId = process.env.LARK_APP_ID, appSecret = process.env.LARK_APP_SECRET;
  if (!appId || !appSecret) throw new Error('LARK_APP_ID / LARK_APP_SECRET not set');
  const res  = await fetch(`${LARK_API}/auth/v3/tenant_access_token/internal`, {
    method:'POST', headers:{ 'Content-Type':'application/json' },
    body: JSON.stringify({ app_id:appId, app_secret:appSecret })
  });
  const json = await res.json();
  if (json.code !== 0) throw new Error(`token ${json.code}: ${json.msg}`);
  _tok = { value:json.tenant_access_token,
           exp: Date.now() + Math.max(60,(json.expire||7200)-60)*1000 };
  return _tok.value;
}

async function uploadToLark(buffer) {
  const token = await tenantToken();
  const boundary = '----sii' + crypto.randomBytes(12).toString('hex');
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="image_type"\r\n\r\nmessage\r\n` +
    `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="drop.jpg"\r\n` +
    `Content-Type: image/jpeg\r\n\r\n`);
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([head, buffer, tail]);
  const res = await fetch(`${LARK_API}/im/v1/images`, {
    method:'POST',
    headers:{ Authorization:`Bearer ${token}`,
              'Content-Type':`multipart/form-data; boundary=${boundary}`,
              'Content-Length':String(body.length) },
    body
  });
  const json = await res.json();
  if (json.code !== 0) throw new Error(`image ${json.code}: ${json.msg}`);
  return json.data.image_key;
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
    qty, receivingPerson, remarks, photos, photoData,
    dropNo, dropTotal, timeIn, timeOut, boxes, vanLoad
  } = req.body || {};

  // Header leads with the truck and driver — in a shared chat that's what tells
  // you whose message this is at a glance. The customer is in the first line.
  const who = [plate, driver].filter(Boolean).join(' · ') || 'SII Logistics';

  const EVENTS = {
    in:    { title: () => `${who} — Sign in`,          head: 'Arrived',            template: 'blue'      },
    out:   { title: () => `${who} — Sign out`,         head: 'Departed',           template: 'green'     },
    start: { title: () => `${who} — Journey started`,  head: 'Left the warehouse', template: 'turquoise' },
    end:   { title: () => `${who} — Journey completed`,head: 'Back at warehouse',  template: 'grey'      }
  };
  const cfg = EVENTS[event];
  if (!cfg) return res.status(400).json({ error: "event must be in, out, start or end" });

  const arriving = event === 'in';
  const isTrip   = event === 'start' || event === 'end';
  const when = at ? new Date(at) : new Date();
  const dateStr = when.toLocaleDateString('en-PH', { timeZone:'Asia/Manila', month:'2-digit', day:'2-digit', year:'numeric' });
  const timeStr = when.toLocaleTimeString('en-PH', { timeZone:'Asia/Manila', hour:'2-digit', minute:'2-digit', hour12:true });

  const hasFix = Number.isFinite(Number(lat)) && Number.isFinite(Number(lng));
  const address = hasFix ? await reverseGeocode(lat, lng) : null;
  const mapUrl  = hasFix ? `https://www.google.com/maps/search/?api=1&query=${lat},${lng}` : null;

  const headline = isTrip
    ? `**${cfg.head}**`
    : `**${esc(customer || 'Stop')} — ${cfg.head}**${dropNo ? `  ·  Drop ${dropNo} of ${dropTotal}` : ''}`;

  const el = [
    md(headline),
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

  if (event === 'start' && (boxes || vanLoad)) {
    el.push({ tag:'hr' });
    el.push(two(`**Boxes loaded**\n${esc(String(boxes ?? '—'))}`, `**Van load**\n${esc(vanLoad || '—')}`));
  }

  if (event === 'out') {
    el.push({ tag:'hr' });
    el.push(two(`**Received by**\n${esc(receivingPerson || '—')}`, `**Qty**\n${esc(String(qty ?? '—'))}`));
    if (timeIn || timeOut) el.push(two(`**Time in**\n${esc(timeIn || '—')}`, `**Time out**\n${esc(timeOut || '—')}`));
    if (remarks) el.push(md(`**Remarks**\n${esc(remarks)}`));
  }

  // Attach the driver's photos at full width. Best-effort: if Lark rejects an
  // upload we still post the card, because the check-in matters more than the
  // picture. mode fit_horizontal is what makes it render large rather than as
  // a thumbnail.
  let photosSent = 0, photoError = null;
  const addPhoto = async buf => {
    const key = await uploadToLark(buf);
    el.push({ tag:'img', img_key:key, mode:'fit_horizontal', preview:true,
              alt:{ tag:'plain_text', content: customer || 'Delivery photo' } });
    photosSent++;
  };

  // Already-uploaded photos come through as URLs on our own public blob store
  for (const url of (Array.isArray(req.body.photoUrls) ? req.body.photoUrls : []).slice(0, 4)) {
    try {
      const r = await fetch(url);
      if (!r.ok) throw new Error(`fetch ${r.status}`);
      await addPhoto(Buffer.from(await r.arrayBuffer()));
    } catch (e) { photoError = e.message; console.error('photo by url:', e.message); break; }
  }

  // Photos still sitting in the driver's offline queue arrive as base64
  for (const p of (Array.isArray(photoData) ? photoData : []).slice(0, 4)) {
    try {
      const b64 = String(p).replace(/^data:image\/\w+;base64,/, '');
      await addPhoto(Buffer.from(b64, 'base64'));
    } catch (e) { photoError = e.message; console.error('photo by data:', e.message); break; }
  }
  if (!photosSent && photos) {
    el.push(md(`📷 ${photos} photo${photos !== 1 ? 's' : ''} saved in the slip`));
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
          template: cfg.template,
          title: { tag:'plain_text', content: cfg.title() }
        },
        elements: el
      }
    });
    return res.json({ ok:true, address, mapUrl, photosSent, photoError });
  } catch (e) {
    console.error('/api/checkin failed:', e.message);
    return res.status(502).json({ ok:false, error:e.message });
  }
};
