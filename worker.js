// Canteen Donut Petition - Cloudflare Worker (API only) + D1
// The web pages are in public/ (index.html and admin.html), served as static assets.
//
// Bindings needed: DB (D1 database).
// Secret needed for the admin panel: ADMIN_KEY.
// OPTIONAL, for email confirmation (needs a domain you own, verified in Resend):
//   RESEND_API_KEY  - API key from resend.com
//   FROM_EMAIL      - e.g. donuts@yourdomain.com
// If those two are not set, signups count straight away (no confirmation email).

const DEFAULT_GOAL = 100; // the admin can change the goal from the admin page

// Every new signup waits for this one admin to approve it before it counts.
// Set REQUIRE_APPROVAL to false to count signups straight away again.
const REQUIRE_APPROVAL = true;
const APPROVER = 'elnathan nandakumaran';
// Letters, numbers, dot, dash, underscore only. No "+" so nobody can sign many
// times with name+1@..., name+2@... (they all land in the same inbox).
const SCHOOL_EMAIL = /^[a-z0-9._-]+@salesian\.vic\.edu\.au$/;

// ---------- Name check ----------
// Catches obvious fake names (keyboard mashing, "test", cartoon characters, numbers).
// It can NOT know if a realistic name belongs to a real person.
const NAME_ERROR = 'Please enter your real first and last name.';
const VOWELS = 'aeiouyàáâäãåæèéêëìíîïòóôöõøùúûüœ';
const BAD_WORDS = new Set([
  'test', 'testing', 'fake', 'name', 'anonymous', 'anon', 'nobody', 'none', 'null',
  'undefined', 'admin', 'donut', 'donuts', 'doughnut', 'user', 'student', 'person',
  'fuck', 'shit', 'bitch', 'cunt', 'penis', 'vagina', 'poop', 'fart', 'butt',
]);
const MASHES = ['asdf', 'qwer', 'zxcv', 'hjkl', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'xcvb', 'lkjh', 'poiu', 'mnbv'];
const FAKE_NAMES = [
  'john doe', 'jane doe', 'first last', 'your name', 'full name', 'no name', 'mickey mouse',
  'donald duck', 'elon musk', 'bill gates', 'homer simpson', 'bart simpson', 'spongebob squarepants',
  'darth vader', 'harry potter', 'santa claus', 'mr donut', 'big chungus', 'john cena',
  'jeff bezos', 'mark zuckerberg', 'taylor swift', 'donald trump', 'joe biden',
];

// Returns an error message, or null if the name looks real.
function validateName(raw) {
  const name = String(raw || '').trim().replace(/\s+/g, ' ');
  if (name.length < 3 || name.length > 60) return NAME_ERROR;

  const words = name.split(' ');
  if (words.length < 2 || words.length > 5) return NAME_ERROR;

  // Letters only (hyphens, apostrophes and a full stop are fine: O'Brien, Smith-Jones)
  if (!words.every(w => /^\p{L}[\p{L}'’.-]*$/u.test(w))) return NAME_ERROR;

  const lower = name.toLowerCase();
  if (FAKE_NAMES.includes(lower)) return NAME_ERROR;

  const letters = words.map(w => w.replace(/[^\p{L}]/gu, '').toLowerCase());
  if (letters.some(w => w.length === 0)) return NAME_ERROR;

  // First and last name need at least 2 letters (a middle initial is fine)
  if (letters[0].length < 2 || letters[letters.length - 1].length < 2) return NAME_ERROR;

  // Same word repeated: "Sam Sam"
  if (new Set(letters).size === 1) return NAME_ERROR;

  // A letter 3+ times in a row: "Jaaaayden"
  if (/(\p{L})\1\1/u.test(letters.join(' '))) return NAME_ERROR;

  const vowelRe = new RegExp('[' + VOWELS + ']');
  const consonantRunRe = new RegExp('[^' + VOWELS + ']{6,}', 'u');
  for (const w of letters) {
    if (BAD_WORDS.has(w)) return NAME_ERROR;
    if (MASHES.some(m => w.includes(m))) return NAME_ERROR;
    if (w.length >= 3 && !vowelRe.test(w)) return NAME_ERROR;   // "Bcdfg"
    if (consonantRunRe.test(w)) return NAME_ERROR;               // "Kjhgfds"
  }
  return null;
}

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

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Robots-Tag': 'noindex',
    },
  });
}

// ---------- Database setup (runs once per Worker start) ----------
let schemaReady = false;
async function ensureSchema(env) {
  if (schemaReady) return;
  // Older databases don't have these columns yet. Errors just mean "already there".
  const alters = [
    'ALTER TABLE signatures ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 1',
    'ALTER TABLE signatures ADD COLUMN confirm_token TEXT',
    'ALTER TABLE signatures ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE signatures ADD COLUMN approved INTEGER NOT NULL DEFAULT 1',
  ];
  for (const sql of alters) {
    try { await env.DB.prepare(sql).run(); } catch (e) { /* column exists */ }
  }
  await env.DB.prepare(
    'CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)'
  ).run();
  schemaReady = true;
}

// Admin can pause the whole petition (no new signups) and resume it later.
async function isPaused(env) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'paused'").first();
  return Boolean(row && row.value === '1');
}

// The goal number shown on the page. Set from the admin page, else the default.
async function getGoal(env) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'goal'").first();
  const n = row ? parseInt(row.value, 10) : NaN;
  return Number.isInteger(n) && n >= 1 ? n : DEFAULT_GOAL;
}

function newToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}

function emailEnabled(env) {
  return Boolean(env.RESEND_API_KEY && env.FROM_EMAIL);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function sendConfirmEmail(env, origin, name, email, token) {
  const link = origin + '/api/confirm?token=' + token;
  const safeName = escapeHtml(name);
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + env.RESEND_API_KEY,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to: [email],
      subject: 'Confirm your YES to donuts in the canteen',
      text: 'Hi ' + name + ',\n\nTap this link to confirm your yes to donuts in the canteen:\n' + link + '\n\nIf you did not sign the petition, ignore this email.',
      html:
        '<div style="font-family:system-ui,Arial,sans-serif;max-width:480px">' +
        '<h2>Donuts in the Canteen</h2>' +
        '<p>Hi ' + safeName + ',</p>' +
        '<p>Tap the button to confirm your YES.</p>' +
        '<p><a href="' + link + '" style="display:inline-block;background:#ff7eb6;color:#3b0d24;padding:12px 18px;border-radius:10px;text-decoration:none;font-weight:700">Confirm my yes</a></p>' +
        '<p style="color:#777;font-size:13px">If you did not sign the petition, ignore this email.</p>' +
        '</div>',
    }),
  });
  return res.ok;
}

// ---------- Admin auth ----------
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

// To get into the admin page you need BOTH the secret ADMIN_KEY and one of these names.
const ADMIN_NAMES = [
  'jayden narayan',
  'elnathan nandakumaran',
  'olivia raphael',
  'mr bourbon',
  'mr. bourbon',
];

function normName(s) {
  return String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

function isAdmin(request, env) {
  if (!env.ADMIN_KEY) return false;
  const h = request.headers.get('Authorization') || '';
  const key = h.startsWith('Bearer ') ? h.slice(7) : '';

  let rawName = request.headers.get('X-Admin-Name') || '';
  try { rawName = decodeURIComponent(rawName); } catch (e) {}
  const name = normName(rawName);

  // Check both every time so the answer takes the same time either way.
  const keyOk = safeEqual(key, env.ADMIN_KEY);
  const nameOk = ADMIN_NAMES.some(n => safeEqual(n, name));
  return keyOk && nameOk;
}

// True when the logged-in admin is the one person who approves signups.
// (Only call this after the admin check has passed.)
function isApprover(request) {
  let rawName = request.headers.get('X-Admin-Name') || '';
  try { rawName = decodeURIComponent(rawName); } catch (e) {}
  return normName(rawName) === APPROVER;
}

// Stops other admins from touching a request that is still waiting for approval.
async function guardWaiting(request, env, id) {
  if (isApprover(request)) return null;
  const row = await env.DB.prepare('SELECT approved FROM signatures WHERE id = ?').bind(id).first();
  if (row && !row.approved) {
    return json({ error: 'Only Elnathan Nandakumaran can handle approval requests.' }, 403);
  }
  return null;
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
  return json({ error: 'Wrong name or key. ' + left + ' attempt' + (left === 1 ? '' : 's') + ' left.' }, 401);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---------- Public ----------
    if (request.method === 'GET' && path === '/api/stats') {
      await ensureSchema(env);
      const total = await env.DB.prepare('SELECT COUNT(*) AS c FROM signatures WHERE confirmed = 1 AND approved = 1 AND blocked = 0').first();
      const recent = await env.DB.prepare(
        'SELECT name, comment FROM signatures WHERE confirmed = 1 AND approved = 1 AND blocked = 0 ORDER BY id DESC LIMIT 20'
      ).all();
      return json({ count: total.c, goal: await getGoal(env), paused: await isPaused(env), recent: recent.results });
    }

    if (request.method === 'POST' && path === '/api/sign') {
      await ensureSchema(env);
      if (await isPaused(env)) {
        return json({ error: 'Signups are paused right now. Please check back later.' }, 403);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }

      // Honeypot: bots fill this in, humans never see it.
      if (body.website) return json({ ok: true });

      const name = String(body.name || '').trim().replace(/\s+/g, ' ').slice(0, 80);
      const email = String(body.email || '').trim().toLowerCase().slice(0, 120);
      const comment = String(body.comment || '').trim().slice(0, 300);

      const nameError = validateName(name);
      if (nameError) return json({ error: nameError }, 400);
      if (!SCHOOL_EMAIL.test(email)) {
        return json({ error: 'School email only. It must end in @salesian.vic.edu.au' }, 400);
      }

      const useEmail = emailEnabled(env);
      const existing = await env.DB.prepare(
        'SELECT id, confirmed, blocked FROM signatures WHERE email = ?'
      ).bind(email).first();

      // An admin blocked this email.
      if (existing && existing.blocked) {
        return json({ error: 'This email can not sign the petition.' }, 403);
      }

      // Already counted (or, with emails off, already in the list).
      if (existing && (existing.confirmed || !useEmail)) {
        return json({ error: 'That email has already said yes. Thank you!' }, 409);
      }

      // No confirmation emails set up: count the yes straight away.
      if (!useEmail) {
        try {
          await env.DB.prepare(
            'INSERT INTO signatures (name, email, comment, confirmed, approved) VALUES (?, ?, ?, 1, ?)'
          ).bind(name, email, comment || null, REQUIRE_APPROVAL ? 0 : 1).run();
        } catch (e) {
          if (String(e).includes('UNIQUE')) {
            return json({ error: 'That email has already said yes. Thank you!' }, 409);
          }
          return json({ error: 'Could not save your yes. Please try again.' }, 500);
        }
        return json({ ok: true, awaiting: REQUIRE_APPROVAL });
      }

      // Confirmation emails on: save as pending, then email a link.
      const token = newToken();
      try {
        if (existing) {
          // Signed before but never confirmed: refresh the details and resend.
          await env.DB.prepare(
            'UPDATE signatures SET name = ?, comment = ?, confirm_token = ? WHERE id = ?'
          ).bind(name, comment || null, token, existing.id).run();
        } else {
          await env.DB.prepare(
            'INSERT INTO signatures (name, email, comment, confirmed, confirm_token, approved) VALUES (?, ?, ?, 0, ?, ?)'
          ).bind(name, email, comment || null, token, REQUIRE_APPROVAL ? 0 : 1).run();
        }
      } catch (e) {
        if (String(e).includes('UNIQUE')) {
          return json({ error: 'That email has already said yes. Thank you!' }, 409);
        }
        return json({ error: 'Could not save your yes. Please try again.' }, 500);
      }

      const sent = await sendConfirmEmail(env, url.origin, name, email, token);
      if (!sent) {
        return json({ error: 'Could not send the confirmation email. Please try again later.' }, 500);
      }
      return json({ ok: true, pending: true });
    }

    // The emailed link lands here. It shows a button (so mail scanners that
    // pre-open links can't confirm by accident); pressing it sends a POST.
    if (path === '/api/confirm' && request.method === 'GET') {
      const token = url.searchParams.get('token') || '';
      if (!/^[a-f0-9]{64}$/.test(token)) return Response.redirect(url.origin + '/?confirmed=0', 302);
      return html(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
        '<meta name="robots" content="noindex"><title>Confirm your yes</title></head>' +
        '<body style="font-family:system-ui,Arial,sans-serif;background:#fff6ea;color:#2b1a18;display:grid;place-items:center;min-height:100vh;margin:0">' +
        '<form method="POST" action="/api/confirm" style="background:#fff;padding:32px;border-radius:16px;box-shadow:0 6px 24px rgba(74,44,42,.12);text-align:center;max-width:380px">' +
        '<h2 style="margin-top:0;color:#4a2c2a">Donuts in the Canteen</h2>' +
        '<p>One last step. Press the button to count your YES.</p>' +
        '<input type="hidden" name="token" value="' + token + '">' +
        '<button type="submit" style="width:100%;padding:14px;border:0;border-radius:12px;background:#ff7eb6;color:#3b0d24;font-size:1.05rem;font-weight:700;cursor:pointer">Confirm my yes</button>' +
        '</form></body></html>'
      );
    }

    if (path === '/api/confirm' && request.method === 'POST') {
      await ensureSchema(env);
      let token = '';
      try {
        const form = await request.formData();
        token = String(form.get('token') || '');
      } catch (e) {}
      if (!/^[a-f0-9]{64}$/.test(token)) return Response.redirect(url.origin + '/?confirmed=0', 303);
      const res = await env.DB.prepare(
        'UPDATE signatures SET confirmed = 1, confirm_token = NULL WHERE confirm_token = ? AND confirmed = 0'
      ).bind(token).run();
      const changed = res.meta && res.meta.changes > 0;
      return Response.redirect(url.origin + '/?confirmed=' + (changed ? '1' : '0'), 303);
    }

    // ---------- Admin (needs ADMIN_KEY) ----------
    if (path === '/api/admin/list' && request.method === 'GET') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      await ensureSchema(env);
      const all = await env.DB.prepare(
        'SELECT id, name, email, comment, created_at, confirmed, blocked, approved FROM signatures ORDER BY id DESC'
      ).all();
      // Requests waiting for approval are only shown to the approver.
      const approver = isApprover(request);
      const rows = approver ? all.results : all.results.filter(r => r.approved);
      const confirmedCount = rows.filter(r => r.confirmed && r.approved && !r.blocked).length;
      const blockedCount = rows.filter(r => r.blocked).length;
      const pendingCount = rows.filter(r => !r.confirmed && !r.blocked).length;
      const awaitingCount = rows.filter(r => r.confirmed && !r.approved && !r.blocked).length;
      return json({
        goal: await getGoal(env),
        count: confirmedCount,
        pending: pendingCount,
        awaiting: awaitingCount,
        blocked: blockedCount,
        isApprover: approver,
        paused: await isPaused(env),
        emailOn: emailEnabled(env),
        rows,
      });
    }

    if (path === '/api/admin/delete' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      const id = Number(body.id);
      if (!Number.isInteger(id)) return json({ error: 'Bad id.' }, 400);
      const blockedByGuard = await guardWaiting(request, env, id);
      if (blockedByGuard) return blockedByGuard;
      await env.DB.prepare('DELETE FROM signatures WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }

    // Approve a waiting request (or all of them). Only the approver can do this.
    if (path === '/api/admin/approve' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      if (!isApprover(request)) {
        return json({ error: 'Only Elnathan Nandakumaran can approve requests.' }, 403);
      }
      await ensureSchema(env);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      if (body.all) {
        await env.DB.prepare(
          'UPDATE signatures SET approved = 1 WHERE confirmed = 1 AND approved = 0 AND blocked = 0'
        ).run();
        return json({ ok: true });
      }
      const id = Number(body.id);
      if (!Number.isInteger(id)) return json({ error: 'Bad id.' }, 400);
      await env.DB.prepare('UPDATE signatures SET approved = 1 WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }

    // Change the goal number (how many people the petition is aiming for).
    if (path === '/api/admin/goal' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      await ensureSchema(env);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      const goal = Number(body.goal);
      if (!Number.isInteger(goal) || goal < 1 || goal > 100000) {
        return json({ error: 'Goal must be a whole number from 1 to 100000.' }, 400);
      }
      await env.DB.prepare(
        "INSERT INTO settings (key, value) VALUES ('goal', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      ).bind(String(goal)).run();
      return json({ ok: true, goal });
    }

    // Block or unblock one person. Blocked people are not counted or shown
    // publicly, and can not sign again. Unblocking puts them back.
    if (path === '/api/admin/block' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      await ensureSchema(env);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      const id = Number(body.id);
      if (!Number.isInteger(id)) return json({ error: 'Bad id.' }, 400);
      const blockedByGuard = await guardWaiting(request, env, id);
      if (blockedByGuard) return blockedByGuard;
      await env.DB.prepare('UPDATE signatures SET blocked = ? WHERE id = ?')
        .bind(body.blocked ? 1 : 0, id).run();
      return json({ ok: true });
    }

    // Pause or resume the whole petition.
    if (path === '/api/admin/pause' && request.method === 'POST') {
      const denied = await checkAdmin(request, env);
      if (denied) return denied;
      await ensureSchema(env);
      let body;
      try { body = await request.json(); } catch { return json({ error: 'Invalid request.' }, 400); }
      await env.DB.prepare(
        "INSERT INTO settings (key, value) VALUES ('paused', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
      ).bind(body.paused ? '1' : '0').run();
      return json({ ok: true, paused: Boolean(body.paused) });
    }

    return new Response('Not found', { status: 404 });
  },
};
