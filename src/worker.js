const ALLOWED_ORIGIN = 'https://psy-cert.com.ua';
const RATE_LIMIT = 3;
const RATE_WINDOW_HOURS = 24;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function corsHeaders(origin) {
  const allowed = origin === ALLOWED_ORIGIN || origin === 'http://localhost:8788';
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function corsHeadersGet(origin) {
  const allowed = origin === ALLOWED_ORIGIN || origin === 'http://localhost:8788';
  return {
    'Access-Control-Allow-Origin': allowed ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

async function hashIp(ip) {
  if (!ip) return null;
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function handleSubscribe(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeaders(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ success: false, error: 'Method not allowed' }), {
      status: 405, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  let email, botcheck, source;
  const ct = request.headers.get('Content-Type') || '';

  if (ct.includes('application/json')) {
    const body = await request.json().catch(() => ({}));
    email = (body.email || '').trim().toLowerCase();
    botcheck = body.botcheck;
    source = body.source || 'index';
  } else {
    const fd = await request.formData().catch(() => new FormData());
    email = ((fd.get('email') || '')).trim().toLowerCase();
    botcheck = fd.get('botcheck');
    source = fd.get('source') || 'index';
  }

  if (botcheck) {
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  if (!email || !EMAIL_RE.test(email)) {
    return new Response(JSON.stringify({ success: false, error: 'invalid_email' }), {
      status: 422, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const ip = request.headers.get('CF-Connecting-IP');
  const ip_hash = await hashIp(ip);

  if (ip_hash) {
    const since = new Date(Date.now() - RATE_WINDOW_HOURS * 3600 * 1000).toISOString();
    const { results } = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM subscribers WHERE ip_hash = ? AND created_at > ?`
    ).bind(ip_hash, since).all();
    if (results[0]?.cnt >= RATE_LIMIT) {
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }
  }

  await env.DB.prepare(
    `INSERT OR IGNORE INTO subscribers (email, ip_hash, source) VALUES (?, ?, ?)`
  ).bind(email, ip_hash, source).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

async function handlePsychologistRegister(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeaders(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ success: false, error: 'Method not allowed' }), {
      status: 405, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  let name, email, city, specialization, experience_years, has_certificate, bio, website, botcheck, source;
  const ct = request.headers.get('Content-Type') || '';

  if (ct.includes('application/json')) {
    const body = await request.json().catch(() => ({}));
    name = (body.name || '').trim();
    email = (body.email || '').trim().toLowerCase();
    city = (body.city || '').trim() || null;
    specialization = (body.specialization || '').trim() || null;
    experience_years = body.experience_years;
    has_certificate = body.has_certificate;
    bio = (body.bio || '').trim() || null;
    website = (body.website || '').trim() || null;
    botcheck = body.botcheck;
    source = body.source || 'for-psychologists';
  } else {
    const fd = await request.formData().catch(() => new FormData());
    name = ((fd.get('name') || '')).trim();
    email = ((fd.get('email') || '')).trim().toLowerCase();
    city = ((fd.get('city') || '')).trim() || null;
    specialization = ((fd.get('specialization') || '')).trim() || null;
    experience_years = fd.get('experience_years');
    has_certificate = fd.get('has_certificate');
    bio = ((fd.get('bio') || '')).trim() || null;
    website = ((fd.get('website') || '')).trim() || null;
    botcheck = fd.get('botcheck');
    source = fd.get('source') || 'for-psychologists';
  }

  if (botcheck) {
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  if (!name || name.length > 100) {
    return new Response(JSON.stringify({ success: false, error: 'invalid_name' }), {
      status: 422, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  if (!email || !EMAIL_RE.test(email)) {
    return new Response(JSON.stringify({ success: false, error: 'invalid_email' }), {
      status: 422, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  // Sanitize bio and website
  if (bio && bio.length > 1000) bio = bio.slice(0, 1000);
  if (website) {
    try { new URL(website); } catch { website = null; }
  }

  const expYears = Number.parseInt(experience_years, 10);
  const experienceYearsVal = Number.isFinite(expYears) ? expYears : null;
  const hasCertificateVal =
    has_certificate === true || has_certificate === 1 ||
    has_certificate === '1' || has_certificate === 'on' || has_certificate === 'true'
      ? 1 : 0;

  const ip = request.headers.get('CF-Connecting-IP');
  const ip_hash = await hashIp(ip);

  if (ip_hash) {
    const since = new Date(Date.now() - RATE_WINDOW_HOURS * 3600 * 1000).toISOString();
    const { results } = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM psychologists WHERE ip_hash = ? AND created_at > ?`
    ).bind(ip_hash, since).all();
    if (results[0]?.cnt >= RATE_LIMIT) {
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...cors, 'Content-Type': 'application/json' },
      });
    }
  }

  const public_id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT OR IGNORE INTO psychologists
       (name, email, city, specialization, experience_years, has_certificate, bio, website, ip_hash, source, public_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(name, email, city, specialization, experienceYearsVal, hasCertificateVal, bio, website, ip_hash, source, public_id).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

// GET /api/registry — public list of published psychologists
async function handleRegistry(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeadersGet(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const url = new URL(request.url);
  const city = url.searchParams.get('city') || null;
  const specialization = url.searchParams.get('specialization') || null;

  let query = `SELECT name, city, specialization, experience_years, has_certificate, public_id, bio, website, created_at
               FROM psychologists WHERE status = 'published'`;
  const params = [];

  if (city) { query += ` AND city = ?`; params.push(city); }
  if (specialization) { query += ` AND specialization = ?`; params.push(specialization); }
  query += ` ORDER BY created_at DESC LIMIT 200`;

  const { results } = await env.DB.prepare(query).bind(...params).all();

  return new Response(JSON.stringify({ success: true, data: results }), {
    headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=300' },
  });
}

// GET /api/p/:public_id — single psychologist profile
async function handleProfile(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeadersGet(origin);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: cors });
  }

  const url = new URL(request.url);
  // pathname: /api/p/some-uuid
  const public_id = url.pathname.replace('/api/p/', '').replace(/\/$/, '');

  if (!public_id || public_id.length < 5) {
    return new Response(JSON.stringify({ success: false, error: 'not_found' }), {
      status: 404, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  const { results } = await env.DB.prepare(
    `SELECT name, city, specialization, experience_years, has_certificate, bio, website, public_id, created_at
     FROM psychologists WHERE public_id = ? AND status = 'published'`
  ).bind(public_id).all();

  if (!results.length) {
    return new Response(JSON.stringify({ success: false, error: 'not_found' }), {
      status: 404, headers: { ...cors, 'Content-Type': 'application/json' },
    });
  }

  return new Response(JSON.stringify({ success: true, data: results[0] }), {
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

// GET /api/admin/list — all psychologists (admin only)
async function handleAdminList(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!env.ADMIN_SECRET || authHeader !== `Bearer ${env.ADMIN_SECRET}`) {
    return new Response(JSON.stringify({ success: false, error: 'unauthorized' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }

  const { results } = await env.DB.prepare(
    `SELECT id, name, email, city, specialization, experience_years, has_certificate, bio, website, status, public_id, created_at
     FROM psychologists ORDER BY created_at DESC`
  ).all();

  return new Response(JSON.stringify({ success: true, data: results }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// POST /api/admin/status — change psychologist status (admin only)
async function handleAdminStatus(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!env.ADMIN_SECRET || authHeader !== `Bearer ${env.ADMIN_SECRET}`) {
    return new Response(JSON.stringify({ success: false, error: 'unauthorized' }), {
      status: 401, headers: { 'Content-Type': 'application/json' },
    });
  }

  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ success: false, error: 'Method not allowed' }), {
      status: 405, headers: { 'Content-Type': 'application/json' },
    });
  }

  const body = await request.json().catch(() => ({}));
  const { public_id, status } = body;

  const VALID = ['pending', 'approved', 'published', 'rejected'];
  if (!public_id || !VALID.includes(status)) {
    return new Response(JSON.stringify({ success: false, error: 'invalid_params' }), {
      status: 422, headers: { 'Content-Type': 'application/json' },
    });
  }

  await env.DB.prepare(`UPDATE psychologists SET status = ? WHERE public_id = ?`).bind(status, public_id).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

/* ─── Кабінет: passwordless-вхід за кодом + збереження розрахунків ─── */

const CODE_TTL_MIN = 10;
const SESSION_TTL_DAYS = 90;
const CODE_MAX_ATTEMPTS = 5;
const CALC_MAX_BYTES = 10 * 1024;

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function json(body, status, cors) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { ...(cors || {}), 'Content-Type': 'application/json' },
  });
}

async function readJsonBody(request) {
  return request.json().catch(() => ({}));
}

// POST /api/auth/request-code — надіслати одноразовий код на email
async function handleAuthRequestCode(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeaders(origin);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return json({ success: false, error: 'method_not_allowed' }, 405, cors);

  const body = await readJsonBody(request);
  if (body.botcheck) return json({ success: true }, 200, cors);

  const email = (body.email || '').trim().toLowerCase();
  if (!email || !EMAIL_RE.test(email)) return json({ success: false, error: 'invalid_email' }, 422, cors);

  const ip_hash = await hashIp(request.headers.get('CF-Connecting-IP'));

  // Rate limit: не більше 5 кодів на email і 10 на IP за годину
  const hourAgo = new Date(Date.now() - 3600 * 1000).toISOString();
  const byEmail = await env.DB.prepare(
    `SELECT COUNT(*) as cnt FROM auth_codes WHERE email = ? AND created_at > ?`
  ).bind(email, hourAgo).all();
  if (byEmail.results[0]?.cnt >= 5) return json({ success: false, error: 'rate_limited' }, 429, cors);
  if (ip_hash) {
    const byIp = await env.DB.prepare(
      `SELECT COUNT(*) as cnt FROM auth_codes WHERE ip_hash = ? AND created_at > ?`
    ).bind(ip_hash, hourAgo).all();
    if (byIp.results[0]?.cnt >= 10) return json({ success: false, error: 'rate_limited' }, 429, cors);
  }

  if (!env.EMAIL) return json({ success: false, error: 'email_unavailable' }, 503, cors);

  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 900000 + 100000);
  const code_hash = await sha256hex(email + ':' + code);
  const expires_at = new Date(Date.now() + CODE_TTL_MIN * 60 * 1000).toISOString();

  await env.DB.prepare(`DELETE FROM auth_codes WHERE email = ?`).bind(email).run();
  await env.DB.prepare(
    `INSERT INTO auth_codes (email, code_hash, expires_at, ip_hash) VALUES (?, ?, ?, ?)`
  ).bind(email, code_hash, expires_at, ip_hash).run();

  try {
    await env.EMAIL.send({
      to: email,
      from: { email: 'noreply@psy-cert.com.ua', name: 'psy-cert.com.ua' },
      subject: `${code} — код входу на psy-cert.com.ua`,
      html: `<p>Ваш код входу до кабінету psy-cert.com.ua:</p><p style="font-size:28px;font-weight:700;letter-spacing:4px">${code}</p><p>Код діє ${CODE_TTL_MIN} хвилин. Якщо ви не запитували вхід — просто проігноруйте цей лист.</p>`,
      text: `Ваш код входу до кабінету psy-cert.com.ua: ${code}\nКод діє ${CODE_TTL_MIN} хвилин. Якщо ви не запитували вхід — проігноруйте цей лист.`,
    });
  } catch (e) {
    return json({ success: false, error: 'email_send_failed' }, 502, cors);
  }

  return json({ success: true }, 200, cors);
}

// POST /api/auth/verify — обміняти код на токен сесії
async function handleAuthVerify(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeaders(origin);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return json({ success: false, error: 'method_not_allowed' }, 405, cors);

  const body = await readJsonBody(request);
  const email = (body.email || '').trim().toLowerCase();
  const code = String(body.code || '').trim();
  if (!email || !EMAIL_RE.test(email) || !/^\d{6}$/.test(code)) {
    return json({ success: false, error: 'invalid_params' }, 422, cors);
  }

  const now = new Date().toISOString();
  const { results } = await env.DB.prepare(
    `SELECT id, code_hash, attempts, expires_at FROM auth_codes WHERE email = ? ORDER BY id DESC LIMIT 1`
  ).bind(email).all();
  const row = results[0];
  if (!row || row.expires_at < now || row.attempts >= CODE_MAX_ATTEMPTS) {
    return json({ success: false, error: 'code_invalid' }, 401, cors);
  }

  const expected = await sha256hex(email + ':' + code);
  if (expected !== row.code_hash) {
    await env.DB.prepare(`UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?`).bind(row.id).run();
    return json({ success: false, error: 'code_invalid' }, 401, cors);
  }

  await env.DB.prepare(`DELETE FROM auth_codes WHERE email = ?`).bind(email).run();

  const token = crypto.randomUUID() + '-' + crypto.randomUUID();
  const token_hash = await sha256hex(token);
  const expires_at = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 3600 * 1000).toISOString();
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)`
  ).bind(token_hash, email, expires_at).run();

  return json({ success: true, token, email }, 200, cors);
}

async function sessionEmail(request, env) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return null;
  const token_hash = await sha256hex(auth.slice(7));
  const { results } = await env.DB.prepare(
    `SELECT email, expires_at FROM sessions WHERE token_hash = ?`
  ).bind(token_hash).all();
  const row = results[0];
  if (!row || row.expires_at < new Date().toISOString()) return null;
  return row.email;
}

// GET/POST /api/calc — збережений розрахунок калькулятора
async function handleCalc(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeadersGet(origin);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  const email = await sessionEmail(request, env);
  if (!email) return json({ success: false, error: 'unauthorized' }, 401, cors);

  if (request.method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT data, updated_at FROM calc_snapshots WHERE email = ?`
    ).bind(email).all();
    return json({ success: true, data: results[0]?.data || null, updated_at: results[0]?.updated_at || null }, 200, cors);
  }

  if (request.method === 'POST') {
    const raw = await request.text();
    if (raw.length > CALC_MAX_BYTES) return json({ success: false, error: 'too_large' }, 413, cors);
    try { JSON.parse(raw); } catch { return json({ success: false, error: 'invalid_json' }, 422, cors); }
    await env.DB.prepare(
      `INSERT INTO calc_snapshots (email, data, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(email) DO UPDATE SET data = excluded.data, updated_at = datetime('now')`
    ).bind(email, raw).run();
    return json({ success: true }, 200, cors);
  }

  return json({ success: false, error: 'method_not_allowed' }, 405, cors);
}

// GET/POST /api/me/profile — профіль психолога в реєстрі, прив'язаний до сесії
async function handleMyProfile(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeadersGet(origin);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  const email = await sessionEmail(request, env);
  if (!email) return json({ success: false, error: 'unauthorized' }, 401, cors);

  if (request.method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT name, city, specialization, experience_years, has_certificate, bio, website, status, public_id, created_at
       FROM psychologists WHERE email = ?`
    ).bind(email).all();
    return json({ success: true, profile: results[0] || null }, 200, cors);
  }

  if (request.method !== 'POST') return json({ success: false, error: 'method_not_allowed' }, 405, cors);

  const body = await readJsonBody(request);
  const name = (body.name || '').trim();
  const city = (body.city || '').trim() || null;
  const specialization = (body.specialization || '').trim() || null;
  let bio = (body.bio || '').trim() || null;
  let website = (body.website || '').trim() || null;

  if (!name || name.length > 100) return json({ success: false, error: 'invalid_name' }, 422, cors);
  if (bio && bio.length > 1000) bio = bio.slice(0, 1000);
  if (website) {
    try { new URL(website); } catch { website = null; }
  }
  const expYears = Number.parseInt(body.experience_years, 10);
  const experienceYearsVal = Number.isFinite(expYears) ? expYears : null;
  const hasCertificateVal = body.has_certificate === true || body.has_certificate === 1 || body.has_certificate === '1' ? 1 : 0;

  const { results } = await env.DB.prepare(
    `SELECT id, public_id FROM psychologists WHERE email = ?`
  ).bind(email).all();

  if (results[0]) {
    // Редагування повертає профіль на модерацію
    await env.DB.prepare(
      `UPDATE psychologists SET name = ?, city = ?, specialization = ?, experience_years = ?,
         has_certificate = ?, bio = ?, website = ?, status = 'pending'
       WHERE email = ?`
    ).bind(name, city, specialization, experienceYearsVal, hasCertificateVal, bio, website, email).run();
  } else {
    const public_id = crypto.randomUUID();
    const ip_hash = await hashIp(request.headers.get('CF-Connecting-IP'));
    await env.DB.prepare(
      `INSERT INTO psychologists
         (name, email, city, specialization, experience_years, has_certificate, bio, website, ip_hash, source, public_id, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'cabinet', ?, 'pending')`
    ).bind(name, email, city, specialization, experienceYearsVal, hasCertificateVal, bio, website, ip_hash, public_id).run();
  }

  const saved = await env.DB.prepare(
    `SELECT name, city, specialization, experience_years, has_certificate, bio, website, status, public_id, created_at
     FROM psychologists WHERE email = ?`
  ).bind(email).all();
  return json({ success: true, profile: saved.results[0] }, 200, cors);
}

// POST /api/auth/logout — завершити сесію
async function handleAuthLogout(request, env) {
  const origin = request.headers.get('Origin') || '';
  const cors = corsHeadersGet(origin); // потрібен заголовок Authorization
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    const token_hash = await sha256hex(auth.slice(7));
    await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?`).bind(token_hash).run();
  }
  return json({ success: true }, 200, cors);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/subscribe') return handleSubscribe(request, env);
    if (url.pathname === '/api/register-psychologist') return handlePsychologistRegister(request, env);
    if (url.pathname === '/api/registry') return handleRegistry(request, env);
    if (url.pathname.startsWith('/api/p/')) return handleProfile(request, env);
    if (url.pathname === '/api/auth/request-code') return handleAuthRequestCode(request, env);
    if (url.pathname === '/api/auth/verify') return handleAuthVerify(request, env);
    if (url.pathname === '/api/auth/logout') return handleAuthLogout(request, env);
    if (url.pathname === '/api/calc') return handleCalc(request, env);
    if (url.pathname === '/api/me/profile') return handleMyProfile(request, env);
    if (url.pathname === '/api/admin/list') return handleAdminList(request, env);
    if (url.pathname === '/api/admin/status') return handleAdminStatus(request, env);

    // Rewrite /p/{uuid}/ and /p/{uuid} to /p/ so the profile SPA can render
    if (url.pathname.startsWith('/p/') && url.pathname !== '/p/') {
      return env.ASSETS.fetch(new Request(new URL('/p/', request.url), request));
    }

    return env.ASSETS.fetch(request);
  },
};
