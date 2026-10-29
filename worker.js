// Canteen Donut Petition - Cloudflare Worker (API only) + D1
// The web pages are in public/ (index.html and admin.html), served as static assets.
// Bindings needed: DB (D1 database).
// Secret needed for the admin panel: ADMIN_KEY (pick a long password).

const GOAL = 150;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex',
    },
  });
}

// Compare two strings without leaking length/position through timing.
function safeEqual(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const len = Math.max(x.length, y.length);
  for (let i = 0; i < len; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

function isAdmin(request, env) {
  if (!env.ADMIN_KEY) return false;
  const h = request.headers.get('Authorization') || '';
  if (!h.startsWith('Bearer ')) return false;
  return safeEqual(h.slice(7), env.ADMIN_KEY);
}

// Lockout: 3 wrong keys from the same IP blocks that IP for 15 minutes.
const MAX_FAILS = 3;
const LOCK_MINUTES = 15;
let attemptsTableReady = false;

// Returns null if the admin key is correct, otherwise a Response to send back.
async function checkAdmin(request, env) {
  if (!attemptsTableReady) {
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS admin_attempts (ip TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0)'
    ).run();
    attemptsTableReady = true;
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT fails, locked_until FROM admin_attempts WHERE ip = ?'
  ).bind(ip).first();

  // Still locked: refuse, even if the key would have been right.
  if (row && row.locked_until > now) {
    const mins = Math.ceil((row.locked_until - now) / 60000);
    return json({ error: 'Too many wrong attempts. Try again in ' + mins + ' minute' + (mins === 1 ? '' : 's') + '.' }, 429);
  }

  if (isAdmin(request, env)) {
    if (row) await env.DB.prepare('DELETE FROM admin_attempts WHERE ip = ?').bind(ip).run();
    return null;
  }

  // Wrong key: count it. An expired lock starts the count fresh.
  const fails = (row && row.locked_until === 0 ? row.fails : 0) + 1;
  if (fails >= MAX_FAILS) {
    await env.DB.prepare(
      'INSERT INTO admin_attempts (ip, fails, locked_until) VALUES (?, 0, ?) ON CONFLICT(ip) DO UPDATE SET fails = 0, locked_until = excluded.locked_until'
    ).bind(ip, now + LOCK_MINUTES * 60000).run();
    return json({ error: 'Too many wrong attempts. Locked for ' + LOCK_MINUTES + ' minutes.' }, 429);
  }
  await env.DB.prepare(
    'INSERT INTO admin_attempts (ip, fails, locked_until) VALUES (?, ?, 0) ON CONFLICT(ip) DO UPDATE SET fails = excluded.fails, locked_until = 0'
  ).bind(ip, fails).run();
  const left = MAX_FAILS - fails;
  return json({ error: 'Wrong key. ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left.' }, 401);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---------- Public ----------
    if (request.method === 'GET' && path === '/api/stats') {
      const total = await env.DB.prepare('SELECT COUNT(*) AS c FROM signatures').first();
      const recent = await env.DB.prepare(
        'SELECT name, comment FROM signatures ORDER BY id DESC LIMIT 20'
      ).all();
      return json({ count: total.c, goal: GOAL, recent: recent.results });
    }

    if (request.method === 'POST' && path === '/api/sign') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }

      // Honeypot: bots fill this in, humans never see it.
      if (body.website) return json({ ok: true });

      const name = String(body.name || '').trim().slice(0, 80);
      const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
      const comment = String(body.comment || '').trim().slice(0, 300);

      if (!name) return json({ error: 'Please enter your name.' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Please enter a valid email.' }, 400);

      try {
        await env.DB.prepare(
          'INSERT INTO signatures (name, email, comment) VALUES (?, ?, ?)'
        ).bind(name, email, comment || null).run();
      } catch (e) {
        if (String(e).includes('UNIQUE')) {
          return json({ error: 'That email has already said yes. Thank you!' }, 409);
        }
        return json({ error: 'Could not save your yes. Please try again.' }, 500);
      }
      return json({ ok: true });
    }

    // ---------- Admin (needs ADMIN_KEY) ----------
    if (path === '/api/admin/list' && request.method === 'GET') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      const rows = await env.DB.prepare(
        'SELECT id, name, email, comment, created_at FROM signatures ORDER BY id DESC'
      ).all();
      return json({ goal: GOAL, count: rows.results.length, rows: rows.results });
    }

    if (path === '/api/admin/delete' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      const id = Number(body.id);
      if (!Number.isInteger(id)) return json({ error: 'Bad id.' }, 400);
      await env.DB.prepare('DELETE FROM signatures WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }

    return new Response('Not found', { status: 404 });
  },
};
