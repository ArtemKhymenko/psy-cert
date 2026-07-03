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

  // silent honeypot
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

  // rate limit: max 3 inserts per ip_hash per 24h
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

  // INSERT OR IGNORE — duplicate email is not an error
  const { meta } = await env.DB.prepare(
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

  let name, email, city, specialization, experience_years, has_certificate, botcheck, source;
  const ct = request.headers.get('Content-Type') || '';

  if (ct.includes('application/json')) {
    const body = await request.json().catch(() => ({}));
    name = (body.name || '').trim();
    email = (body.email || '').trim().toLowerCase();
    city = (body.city || '').trim() || null;
    specialization = (body.specialization || '').trim() || null;
    experience_years = body.experience_years;
    has_certificate = body.has_certificate;
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
    botcheck = fd.get('botcheck');
    source = fd.get('source') || 'for-psychologists';
  }

  // silent honeypot
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

  // normalize optional fields
  const expYears = Number.parseInt(experience_years, 10);
  const experienceYearsVal = Number.isFinite(expYears) ? expYears : null;
  const hasCertificateVal =
    has_certificate === true || has_certificate === 1 ||
    has_certificate === '1' || has_certificate === 'on' || has_certificate === 'true'
      ? 1 : 0;

  const ip = request.headers.get('CF-Connecting-IP');
  const ip_hash = await hashIp(ip);

  // rate limit: max 3 inserts per ip_hash per 24h
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

  // INSERT OR IGNORE — duplicate email is not an error
  const public_id = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT OR IGNORE INTO psychologists
       (name, email, city, specialization, experience_years, has_certificate, ip_hash, source, public_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(name, email, city, specialization, experienceYearsVal, hasCertificateVal, ip_hash, source, public_id).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/subscribe') {
      return handleSubscribe(request, env);
    }
    if (url.pathname === '/api/register-psychologist') {
      return handlePsychologistRegister(request, env);
    }
    return env.ASSETS.fetch(request);
  },
};
