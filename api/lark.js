const crypto = require('crypto');

const SECRET   = process.env.JWT_SECRET || 'sii-dev-secret-CHANGE-IN-PRODUCTION';
const LARK_API = 'https://open.larksuite.com/open-apis';

// Webhook URLs live here, server-side, so they never reach the browser.
// Set these in Vercel → Settings → Environment Variables.
const HOOKS = {
  delivery: process.env.LARK_HOOK_DELIVERY,
  drivers:  process.env.LARK_HOOK_DRIVERS,
  sm:       process.env.LARK_HOOK_SM
};

const LABELS = {
  delivery: 'Delivery team',
  drivers:  'Drivers & Helpers',
  sm:       'SM promodizer'
};

// ── Auth (same HMAC scheme as /api/data) ─────────────────────────────────────
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

// ── Tenant access token, cached for the life of the warm instance ────────────
let _tok = { value: null, exp: 0 };

async function tenantToken() {
  if (_tok.value && Date.now() < _tok.exp) return _tok.value;

  const appId     = process.env.LARK_APP_ID;
  const appSecret = process.env.LARK_APP_SECRET;
  if (!appId || !appSecret) {
    throw new Error('LARK_APP_ID / LARK_APP_SECRET not configured — needed to upload the image');
  }

  const res = await fetch(`${LARK_API}/auth/v3/tenant_access_token/internal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app_id: appId, app_secret: appSecret })
  });
  const json = await res.json();
  if (json.code !== 0) throw new Error(`Lark token failed (${json.code}): ${json.msg}`);

  _tok = {
    value: json.tenant_access_token,
    // expire is in seconds; refresh a minute early
    exp: Date.now() + Math.max(60, (json.expire || 7200) - 60) * 1000
  };
  return _tok.value;
}

// ── Upload the PNG once, reuse the image_key for every chat ──────────────────
async function uploadImage(buffer) {
  const token = await tenantToken();

  const boundary = '----sii' + crypto.randomBytes(12).toString('hex');
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="image_type"\r\n\r\nmessage\r\n` +
    `--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="schedule.png"\r\n` +
    `Content-Type: image/png\r\n\r\n`
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body = Buffer.concat([head, buffer, tail]);

  const res = await fetch(`${LARK_API}/im/v1/images`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Content-Length': String(body.length)
    },
    body
  });
  const json = await res.json();
  if (json.code !== 0) {
    throw new Error(`Image upload failed (${json.code}): ${json.msg}`);
  }
  return json.data.image_key;
}

// One bubble containing the image with the text underneath it.
// Lark's "post" type takes an array of rows; each row is an array of tags.
function buildPost(imageKey, text, title) {
  const rows = [[{ tag: 'img', image_key: imageKey }]];
  for (const line of String(text || '').split('\n')) {
    // Empty text tags get dropped, so use a space to keep the blank line
    rows.push([{ tag: 'text', text: line.length ? line : ' ' }]);
  }
  const body = { title: title || '', content: rows };
  // Supply both locales so it renders regardless of the reader's language setting
  return { msg_type: 'post', content: { post: { en_us: body, zh_cn: body } } };
}

async function postHook(url, payload) {
  const res  = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const json = await res.json().catch(() => ({}));
  // Custom bots reply {code:0} on success; some return {StatusCode:0}
  const ok = json.code === 0 || json.StatusCode === 0 || res.ok;
  if (!ok) throw new Error(json.msg || json.StatusMessage || `HTTP ${res.status}`);
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

  // ── Setup diagnostic: reports exactly which step is broken ──
  if (req.body && req.body.diagnose) {
    const out = {
      hooks: {
        delivery: Boolean(HOOKS.delivery),
        drivers:  Boolean(HOOKS.drivers),
        sm:       Boolean(HOOKS.sm)
      },
      appId:     Boolean(process.env.LARK_APP_ID),
      appSecret: Boolean(process.env.LARK_APP_SECRET),
      tokenOk: false, tokenError: null,
      uploadOk: false, uploadError: null
    };
    try {
      await tenantToken();
      out.tokenOk = true;
    } catch (e) {
      out.tokenError = e.message;
      return res.json(out);
    }
    try {
      // 32x32 solid PNG — verified valid; avoids any minimum-dimension check
      const tiny = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAALElEQVR42u3NQQEAQAQAMC6RBPoX0eNK8NsKLKcrLr04JhAIBAKBQCAQCLZ8nY4BkwF7Q1gAAAAASUVORK5CYII=',
        'base64');
      const key = await uploadImage(tiny);
      out.uploadOk = Boolean(key);
    } catch (e) {
      out.uploadError = e.message;
    }
    return res.json(out);
  }

  const { targets, messages, png, imageTargets } = req.body || {};

  if (!Array.isArray(targets) || !targets.length) {
    return res.status(400).json({ error: 'Pick at least one chat' });
  }
  if (!messages || typeof messages !== 'object') {
    return res.status(400).json({ error: 'messages required' });
  }

  const unknown = targets.filter(t => !HOOKS[t]);
  if (unknown.length) {
    return res.status(400).json({
      error: `No webhook configured for: ${unknown.join(', ')}. Set LARK_HOOK_* env vars in Vercel.`
    });
  }

  // Which chats get the image. Defaults to delivery only; the others are text-only.
  const wantsImage = Array.isArray(imageTargets) ? imageTargets : ['delivery'];
  const imageNeeded = targets.some(t => wantsImage.includes(t));

  // Upload only if a selected chat actually wants it. Text still sends if this fails.
  let imageKey = null, imageError = null;
  if (png && imageNeeded) {
    try {
      const b64 = String(png).replace(/^data:image\/png;base64,/, '');
      imageKey = await uploadImage(Buffer.from(b64, 'base64'));
    } catch (e) {
      imageError = e.message;
      console.error('Lark image upload:', e.message);
    }
  }

  const fallbacks = req.body.fallbackMessages || {};
  const titles    = req.body.titles || {};

  const sent = [], failed = [];
  for (const t of targets) {
    try {
      const withImage = imageKey && wantsImage.includes(t);

      // A chat expecting the image gets the short caption; if the upload failed,
      // fall back to the detailed text so the message still says something useful.
      let text = messages[t];
      if (wantsImage.includes(t) && !imageKey && fallbacks[t]) text = fallbacks[t];

      if (withImage) {
        try {
          await postHook(HOOKS[t], buildPost(imageKey, text, titles[t]));
        } catch (e) {
          // Some tenants restrict rich posts — degrade to two plain messages
          console.error(`post failed for ${t}, falling back:`, e.message);
          if (text) await postHook(HOOKS[t], { msg_type: 'text', content: { text } });
          await postHook(HOOKS[t], { msg_type: 'image', content: { image_key: imageKey } });
        }
      } else if (text) {
        await postHook(HOOKS[t], { msg_type: 'text', content: { text } });
      }
      sent.push(LABELS[t] || t);
    } catch (e) {
      console.error(`Lark send to ${t}:`, e.message);
      failed.push(`${LABELS[t] || t} (${e.message})`);
    }
  }

  return res.status(failed.length && !sent.length ? 502 : 200).json({
    ok: !failed.length,
    sent,
    failed,
    imageSent: Boolean(imageKey),
    imageNeeded,
    imageError
  });
};
