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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/api/subscribe') return handleSubscribe(request, env);
    if (url.pathname === '/api/register-psychologist') return handlePsychologistRegister(request, env);
    if (url.pathname === '/api/registry') return handleRegistry(request, env);
    if (url.pathname.startsWith('/api/p/')) return handleProfile(request, env);
    if (url.pathname === '/api/admin/list') return handleAdminList(request, env);
    if (url.pathname === '/api/admin/status') return handleAdminStatus(request, env);

    // Rewrite /p/{uuid}/ and /p/{uuid} to /p/ so the profile SPA can render
    if (url.pathname.startsWith('/p/') && url.pathname !== '/p/') {
      return env.ASSETS.fetch(new Request(new URL('/p/', request.url), request));
    }

    return env.ASSETS.fetch(request);
  },
};
