// Cloudflare Worker: bridges the website chat widget <-> SMS via Twilio.
//
// Customer -> site chat -> POST /send -> Twilio SMS to the owner's cell:   "[K7QF] Mike: need a shed torn down"
// Owner replies by text to the Twilio number:                              "K7QF We can come Tuesday"
// Worker maps K7QF back to that one visitor's session; only that browser sees the reply (via /messages).
//
// Bindings / secrets (see README.md): KV namespace CHAT, secrets TWILIO_SID, TWILIO_TOKEN,
// vars TWILIO_NUMBER (E.164, the Twilio number), OWNER_NUMBER (E.164, owner's cell), ALLOWED_ORIGIN.

const json = (obj, status = 200, origin = '*') =>
  new Response(JSON.stringify(obj), { status, headers: {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  }});

const SID_RE = /^[0-9a-f]{32}$/;
const TTL = 60 * 60 * 24 * 7; // keep conversations 7 days

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || '*';
    if (req.method === 'OPTIONS') return json({}, 204, origin);

    if (url.pathname === '/send' && req.method === 'POST') return send(req, env, origin);
    if (url.pathname === '/messages' && req.method === 'GET') return messages(url, env, origin);
    if (url.pathname === '/sms' && req.method === 'POST') return inbound(req, env);
    return json({ error: 'not found' }, 404, origin);
  },
};

async function getConv(env, sid) {
  return (await env.CHAT.get(`s:${sid}`, 'json')) || { code: null, msgs: [] };
}
const putConv = (env, sid, c) => env.CHAT.put(`s:${sid}`, JSON.stringify(c), { expirationTtl: TTL });

async function send(req, env, origin) {
  let body; try { body = await req.json(); } catch { return json({ error: 'bad json' }, 400, origin); }
  const sid = String(body.sid || '');
  const text = String(body.text || '').trim().slice(0, 500);
  const name = String(body.name || 'Visitor').trim().slice(0, 40);
  if (!SID_RE.test(sid) || !text) return json({ error: 'bad request' }, 400, origin);

  // crude rate limit: 20 messages per session per conversation window
  const conv = await getConv(env, sid);
  if (conv.msgs.filter(m => m.from === 'visitor').length >= 40) return json({ error: 'limit' }, 429, origin);

  if (!conv.code) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    for (let i = 0; i < 10 && !conv.code; i++) {
      const c = Array.from(crypto.getRandomValues(new Uint8Array(4)), b => alphabet[b % alphabet.length]).join('');
      if (!(await env.CHAT.get(`c:${c}`))) conv.code = c;
    }
    await env.CHAT.put(`c:${conv.code}`, sid, { expirationTtl: TTL });
  }
  const n = conv.msgs.length ? conv.msgs[conv.msgs.length - 1].n + 1 : 1;
  conv.msgs.push({ n, from: 'visitor', text, t: Date.now() });
  await putConv(env, sid, conv);

  const first = conv.msgs.filter(m => m.from === 'visitor').length === 1;
  const sms = `[${conv.code}] ${name}: ${text}` + (first ? `\n(Reply starting with ${conv.code} to answer this customer)` : '');
  const ok = await twilioSend(env, env.OWNER_NUMBER, sms);
  return json({ ok, n }, ok ? 200 : 502, origin);
}

async function messages(url, env, origin) {
  const sid = url.searchParams.get('sid') || '';
  const after = parseInt(url.searchParams.get('after') || '0', 10) || 0;
  if (!SID_RE.test(sid)) return json({ error: 'bad request' }, 400, origin);
  const conv = await getConv(env, sid);
  // visitors only ever receive messages from THEIR OWN session, by unguessable 128-bit id
  return json({ messages: conv.msgs.filter(m => m.n > after && m.from === 'owner') }, 200, origin);
}

// Twilio webhook for incoming SMS (owner's replies)
async function inbound(req, env) {
  const raw = await req.text();
  const params = new URLSearchParams(raw);
  if (!(await validTwilio(req, env, params))) return new Response('forbidden', { status: 403 });
  const twiml = msg => new Response(`<?xml version="1.0"?><Response>${msg ? `<Message>${msg}</Message>` : ''}</Response>`,
    { headers: { 'Content-Type': 'text/xml' } });

  if (params.get('From') !== env.OWNER_NUMBER) return twiml(''); // ignore anyone else texting the number

  const m = (params.get('Body') || '').trim().match(/^\[?#?([A-Za-z0-9]{4})\]?[\s:,-]+([\s\S]+)$/);
  if (!m) return twiml('Start your reply with the 4-character code, e.g.  K7QF Sounds good, see you Tuesday');
  const code = m[1].toUpperCase();
  const sid = await env.CHAT.get(`c:${code}`);
  if (!sid) return twiml(`Unknown or expired code ${code}.`);

  const conv = await getConv(env, sid);
  const n = conv.msgs.length ? conv.msgs[conv.msgs.length - 1].n + 1 : 1;
  conv.msgs.push({ n, from: 'owner', text: m[2].trim().slice(0, 1000), t: Date.now() });
  await putConv(env, sid, conv);
  return twiml('');
}

async function twilioSend(env, to, body) {
  const r = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${env.TWILIO_SID}/Messages.json`, {
    method: 'POST',
    headers: { Authorization: 'Basic ' + btoa(`${env.TWILIO_SID}:${env.TWILIO_TOKEN}`), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: to, From: env.TWILIO_NUMBER, Body: body }),
  });
  return r.ok;
}

// Verify X-Twilio-Signature (HMAC-SHA1 of URL + sorted params)
async function validTwilio(req, env, params) {
  const sig = req.headers.get('X-Twilio-Signature') || '';
  let data = req.url;
  for (const k of [...params.keys()].sort()) data += k + params.get(k);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.TWILIO_TOKEN), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)));
  return btoa(String.fromCharCode(...mac)) === sig;
}
