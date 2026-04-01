/**
 * Guild Manager - Cloudflare Worker
 * Phase 1: Discord OAuth + Team creation + Invite system
 * Phase 2: Shared boss timers per team + Discord webhook notifications
 * Phase 3: Event scheduling + RSVP + attendance
 *
 * Bindings: DB (D1), DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, JWT_SECRET
 */

// --- Helpers ---

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

// Simple JWT-like token using HMAC-SHA256
async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)))));
  return `${data}.${sig}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const expected = new Uint8Array(atob(sig).split('').map(c => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify('HMAC', key, expected, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// --- Database setup ---

async function initDB(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      discord_id TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      avatar TEXT,
      premium INTEGER DEFAULT 0,
      premium_type TEXT,
      premium_until INTEGER,
      ls_customer_id TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      invite_code TEXT UNIQUE NOT NULL,
      max_members INTEGER DEFAULT 5,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      joined_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS bosses (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      interval_ms INTEGER,
      fixed_time TEXT,
      weekly_day INTEGER,
      weekly_time TEXT,
      biweekly_days TEXT,
      alert_minutes INTEGER DEFAULT 5,
      next_spawn INTEGER NOT NULL,
      status TEXT DEFAULT 'waiting',
      spawned_at INTEGER,
      auto_reset_at INTEGER,
      last_death INTEGER,
      warned INTEGER DEFAULT 0,
      spawn_notified INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      event_type TEXT DEFAULT 'other',
      event_time INTEGER NOT NULL,
      duration_minutes INTEGER DEFAULT 60,
      created_by TEXT NOT NULL,
      reminder_sent INTEGER DEFAULT 0,
      start_notified INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_rsvps (
      event_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      status TEXT DEFAULT 'going',
      responded_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (event_id, user_id),
      FOREIGN KEY (event_id) REFERENCES events(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_attendance (
      event_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      attended INTEGER DEFAULT 0,
      PRIMARY KEY (event_id, user_id),
      FOREIGN KEY (event_id) REFERENCES events(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS team_settings (
      team_id TEXT PRIMARY KEY,
      webhook_url TEXT,
      on_warning INTEGER DEFAULT 1,
      on_spawn INTEGER DEFAULT 1,
      timezone TEXT DEFAULT 'Asia/Manila',
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
  ]);
}

// --- Boss timer helpers ---

function getNextFixedSpawn(timeStr, tz) {
  const [h, m] = timeStr.split(':').map(Number);
  const now = new Date();
  const local = new Date(now.toLocaleString('en-US', { timeZone: tz }));
  const spawn = new Date(local);
  spawn.setHours(h, m, 0, 0);
  if (spawn <= local) spawn.setDate(spawn.getDate() + 1);
  const offset = now.getTime() - local.getTime();
  return spawn.getTime() + offset;
}

function getNextWeeklySpawn(targetDay, timeStr, tz) {
  const [h, m] = timeStr.split(':').map(Number);
  const now = new Date();
  const local = new Date(now.toLocaleString('en-US', { timeZone: tz }));
  const spawn = new Date(local);
  spawn.setHours(h, m, 0, 0);
  let daysUntil = targetDay - local.getDay();
  if (daysUntil < 0) daysUntil += 7;
  if (daysUntil === 0 && spawn <= local) daysUntil = 7;
  spawn.setDate(spawn.getDate() + daysUntil);
  const offset = now.getTime() - local.getTime();
  return spawn.getTime() + offset;
}

function getNextBiweeklySpawn(days, tz) {
  const parsed = typeof days === 'string' ? JSON.parse(days) : days;
  return Math.min(...parsed.map(d => getNextWeeklySpawn(d.day, d.time, tz)));
}

function calcNextSpawn(boss, fromTime, tz) {
  if (boss.type === 'interval') return fromTime + boss.interval_ms;
  if (boss.type === 'fixed') return getNextFixedSpawn(boss.fixed_time, tz);
  if (boss.type === 'weekly') return getNextWeeklySpawn(boss.weekly_day, boss.weekly_time, tz);
  if (boss.type === 'biweekly') return getNextBiweeklySpawn(boss.biweekly_days, tz);
  return fromTime + 3600000;
}

async function sendDiscord(webhookUrl, title, description, color) {
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        embeds: [{ title, description, color, footer: { text: 'Guild Manager' }, timestamp: new Date().toISOString() }],
      }),
    });
  } catch (e) { /* ignore */ }
}

// --- Cron handler ---

async function handleScheduled(env) {
  await initDB(env.DB);
  const now = Date.now();

  const bosses = await env.DB.prepare('SELECT * FROM bosses WHERE status = ?').bind('waiting').all();

  for (const boss of bosses.results) {
    const remaining = boss.next_spawn - now;
    const alertMs = (boss.alert_minutes || 5) * 60000;

    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(boss.team_id).first();
    const tz = settings?.timezone || 'Asia/Manila';

    // Warning
    if (remaining > 0 && remaining <= alertMs && !boss.warned) {
      if (settings?.on_warning && settings?.webhook_url) {
        const minLeft = Math.max(1, Math.round(remaining / 60000));
        await sendDiscord(settings.webhook_url, `${boss.name} - Spawning Soon!`,
          `**${boss.name}** spawns in **${minLeft} minute${minLeft !== 1 ? 's' : ''}**!`, 16760576);
      }
      await env.DB.prepare('UPDATE bosses SET warned = 1 WHERE id = ?').bind(boss.id).run();
      continue;
    }

    // Spawned
    if (remaining <= 0) {
      if (!boss.spawn_notified && settings?.on_spawn && settings?.webhook_url) {
        await sendDiscord(settings.webhook_url, `${boss.name} has SPAWNED!`,
          `**${boss.name}** is now available!\nAuto-reset in 5 minutes if not killed.`, 15548997);
      }
      await env.DB.prepare('UPDATE bosses SET status = ?, spawned_at = ?, auto_reset_at = ?, spawn_notified = 1 WHERE id = ?')
        .bind('spawned', now, now + 300000, boss.id).run();
    }
  }

  // Event reminders (15 min before)
  const upcomingEvents = await env.DB.prepare(
    'SELECT * FROM events WHERE event_time > ? AND event_time <= ? AND reminder_sent = 0'
  ).bind(now, now + 15 * 60000).all();

  for (const event of upcomingEvents.results) {
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(event.team_id).first();
    if (settings?.webhook_url) {
      const minLeft = Math.max(1, Math.round((event.event_time - now) / 60000));
      const rsvps = await env.DB.prepare("SELECT COUNT(*) as count FROM event_rsvps WHERE event_id = ? AND status = 'going'").bind(event.id).first();
      await sendDiscord(settings.webhook_url, `${event.title} - Starting Soon!`,
        `**${event.title}** starts in **${minLeft} minute${minLeft !== 1 ? 's' : ''}**!\n${rsvps.count} member${rsvps.count !== 1 ? 's' : ''} going.${event.description ? '\n\n' + event.description : ''}`,
        16760576);
    }
    await env.DB.prepare('UPDATE events SET reminder_sent = 1 WHERE id = ?').bind(event.id).run();
  }

  // Event start notifications
  const startingEvents = await env.DB.prepare(
    'SELECT * FROM events WHERE event_time <= ? AND start_notified = 0'
  ).bind(now).all();

  for (const event of startingEvents.results) {
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(event.team_id).first();
    if (settings?.webhook_url) {
      await sendDiscord(settings.webhook_url, `${event.title} is starting NOW!`,
        `**${event.title}** has started!${event.description ? '\n\n' + event.description : ''}`, 15548997);
    }
    await env.DB.prepare('UPDATE events SET start_notified = 1 WHERE id = ?').bind(event.id).run();
  }

  // Auto-reset spawned bosses
  const spawned = await env.DB.prepare('SELECT * FROM bosses WHERE status = ? AND auto_reset_at <= ?')
    .bind('spawned', now).all();

  for (const boss of spawned.results) {
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(boss.team_id).first();
    const tz = settings?.timezone || 'Asia/Manila';
    const nextSpawn = calcNextSpawn(boss, now, tz);
    await env.DB.prepare('UPDATE bosses SET status = ?, spawned_at = NULL, auto_reset_at = NULL, warned = 0, spawn_notified = 0, next_spawn = ? WHERE id = ?')
      .bind('waiting', nextSpawn, boss.id).run();
  }
}

// --- Routes ---

async function handleRequest(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // Init DB on first request
  await initDB(env.DB);

  // --- Auth routes ---

  // GET /auth/login — redirect to Discord OAuth
  if (path === '/auth/login') {
    const redirect = `https://discord.com/api/oauth2/authorize?client_id=${env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}&response_type=code&scope=identify`;
    return Response.redirect(redirect, 302);
  }

  // GET /auth/callback — Discord OAuth callback
  if (path === '/auth/callback') {
    const code = url.searchParams.get('code');
    if (!code) return json({ error: 'No code provided' }, 400);

    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: url.origin + '/auth/callback',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return json({ error: 'OAuth failed' }, 400);

    // Get Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userRes.json();
    if (!discordUser.id) return json({ error: 'Failed to get user' }, 400);

    // Upsert user in DB
    const userId = crypto.randomUUID();
    const existing = await env.DB.prepare('SELECT id FROM users WHERE discord_id = ?').bind(discordUser.id).first();

    let finalUserId;
    if (existing) {
      finalUserId = existing.id;
      await env.DB.prepare('UPDATE users SET username = ?, avatar = ? WHERE id = ?')
        .bind(discordUser.username, discordUser.avatar, existing.id).run();
    } else {
      finalUserId = userId;
      await env.DB.prepare('INSERT INTO users (id, discord_id, username, avatar) VALUES (?, ?, ?, ?)')
        .bind(userId, discordUser.id, discordUser.username, discordUser.avatar).run();
    }

    // Create JWT
    const jwt = await createToken({
      userId: finalUserId,
      discordId: discordUser.id,
      username: discordUser.username,
    }, env.JWT_SECRET);

    // Redirect to frontend with token
    const frontendUrl = 'https://anomaly-surround.github.io/guild-manager';
    return Response.redirect(`${frontendUrl}?token=${jwt}`, 302);
  }

  // GET /auth/me — get current user
  if (path === '/auth/me') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) return json({ error: 'User not found' }, 404);
    // Check if subscription is still active
    let isPremium = false;
    if (dbUser.premium) {
      if (dbUser.premium_type === 'lifetime') {
        isPremium = true;
      } else if (dbUser.premium_until && dbUser.premium_until > Math.floor(Date.now() / 1000)) {
        isPremium = true;
      } else {
        // Subscription expired
        await env.DB.prepare('UPDATE users SET premium = 0 WHERE id = ?').bind(dbUser.id).run();
      }
    }

    return json({
      id: dbUser.id,
      username: dbUser.username,
      avatar: dbUser.avatar,
      discordId: dbUser.discord_id,
      premium: isPremium,
      premiumType: isPremium ? dbUser.premium_type : null,
    });
  }

  // --- LemonSqueezy webhook (no auth required) ---
  if (path === '/ls/webhook' && request.method === 'POST') {
    const body = await request.json();
    const eventName = body.meta?.event_name;

    if (eventName === 'order_created') {
      const attrs = body.data?.attributes;
      const customData = body.meta?.custom_data;
      const userId = customData?.user_id;
      const variantId = attrs?.first_order_item?.variant_id;

      if (userId) {
        const isLifetime = String(variantId) === env.LS_LIFETIME_VARIANT;
        if (isLifetime) {
          await env.DB.prepare('UPDATE users SET premium = 1, premium_type = ?, ls_customer_id = ? WHERE id = ?')
            .bind('lifetime', String(attrs.customer_id), userId).run();
        } else {
          // Monthly — set expiry 35 days out (gives buffer)
          const until = Math.floor(Date.now() / 1000) + 35 * 86400;
          await env.DB.prepare('UPDATE users SET premium = 1, premium_type = ?, premium_until = ?, ls_customer_id = ? WHERE id = ?')
            .bind('monthly', until, String(attrs.customer_id), userId).run();
        }
      }
    }

    if (eventName === 'subscription_payment_success') {
      const customData = body.meta?.custom_data;
      const userId = customData?.user_id;
      if (userId) {
        const until = Math.floor(Date.now() / 1000) + 35 * 86400;
        await env.DB.prepare('UPDATE users SET premium = 1, premium_until = ? WHERE id = ?')
          .bind(until, userId).run();
      }
    }

    if (eventName === 'subscription_expired' || eventName === 'subscription_cancelled') {
      const customData = body.meta?.custom_data;
      const userId = customData?.user_id;
      if (userId) {
        await env.DB.prepare('UPDATE users SET premium = 0, premium_type = NULL, premium_until = NULL WHERE id = ?')
          .bind(userId).run();
      }
    }

    return json({ ok: true });
  }

  // --- Checkout URL generator ---
  if (path === '/api/checkout' && request.method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const body = await request.json();
    const variant = body.type === 'lifetime' ? env.LS_LIFETIME_VARIANT : env.LS_MONTHLY_VARIANT;

    const res = await fetch('https://api.lemonsqueezy.com/v1/checkouts', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.LS_API_KEY}`,
        'Content-Type': 'application/vnd.api+json',
        'Accept': 'application/vnd.api+json',
      },
      body: JSON.stringify({
        data: {
          type: 'checkouts',
          attributes: {
            checkout_data: {
              custom: { user_id: user.userId },
            },
          },
          relationships: {
            store: { data: { type: 'stores', id: env.LS_STORE_ID } },
            variant: { data: { type: 'variants', id: variant } },
          },
        },
      }),
    });

    const checkout = await res.json();
    const url = checkout.data?.attributes?.url;
    if (!url) return json({ error: 'Failed to create checkout' }, 500);
    return json({ url });
  }

  // --- Protected routes (require auth) ---
  const user = await getUser(request, env);
  if (!user && path.startsWith('/api/')) {
    return json({ error: 'Unauthorized' }, 401);
  }

  // GET /api/teams — list user's teams
  if (path === '/api/teams' && request.method === 'GET') {
    const teams = await env.DB.prepare(`
      SELECT t.*, tm.role,
        (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
      FROM teams t
      JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
      ORDER BY t.created_at DESC
    `).bind(user.userId).all();
    return json({ teams: teams.results });
  }

  // POST /api/teams — create a team
  if (path === '/api/teams' && request.method === 'POST') {
    const body = await request.json();
    if (!body.name || !body.name.trim()) return json({ error: 'Name required' }, 400);

    // Check team limit (free = 1, premium = unlimited)
    const dbUser = await env.DB.prepare('SELECT premium FROM users WHERE id = ?').bind(user.userId).first();
    const isPremium = dbUser?.premium;
    const teamCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM teams WHERE owner_id = ?'
    ).bind(user.userId).first();
    if (!isPremium && teamCount.count >= 1) {
      return json({ error: 'Free tier: 1 team max. Upgrade for more.' }, 403);
    }

    const teamId = crypto.randomUUID();
    const inviteCode = generateInviteCode();

    await env.DB.batch([
      env.DB.prepare('INSERT INTO teams (id, name, owner_id, invite_code) VALUES (?, ?, ?, ?)')
        .bind(teamId, body.name.trim(), user.userId, inviteCode),
      env.DB.prepare('INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)')
        .bind(teamId, user.userId, 'leader'),
    ]);

    return json({ team: { id: teamId, name: body.name.trim(), invite_code: inviteCode } });
  }

  // GET /api/teams/:id — team detail with members
  const teamMatch = path.match(/^\/api\/teams\/([^/]+)$/);
  if (teamMatch && request.method === 'GET') {
    const teamId = teamMatch[1];

    // Check membership
    const membership = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!membership) return json({ error: 'Not a member' }, 403);

    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(teamId).first();
    if (!team) return json({ error: 'Team not found' }, 404);

    const members = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar, u.discord_id, tm.role, tm.joined_at
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = ?
      ORDER BY
        CASE tm.role WHEN 'leader' THEN 0 WHEN 'officer' THEN 1 ELSE 2 END,
        tm.joined_at ASC
    `).bind(teamId).all();

    return json({
      team: { ...team, my_role: membership.role },
      members: members.results,
    });
  }

  // DELETE /api/teams/:id — delete team (leader only)
  const deleteTeamMatch = path.match(/^\/api\/teams\/([^/]+)$/);
  if (deleteTeamMatch && request.method === 'DELETE') {
    const teamId = deleteTeamMatch[1];
    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ? AND owner_id = ?')
      .bind(teamId, user.userId).first();
    if (!team) return json({ error: 'Not the owner' }, 403);

    await env.DB.batch([
      env.DB.prepare('DELETE FROM team_members WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(teamId),
    ]);
    return json({ ok: true });
  }

  // POST /api/teams/:id/members/role — change member role (leader/officer only)
  const roleMatch = path.match(/^\/api\/teams\/([^/]+)\/members\/role$/);
  if (roleMatch && request.method === 'POST') {
    const teamId = roleMatch[1];
    const body = await request.json();

    const myRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!myRole || (myRole.role !== 'leader' && myRole.role !== 'officer')) {
      return json({ error: 'No permission' }, 403);
    }

    // Can't change leader role unless you're the leader
    if (body.role === 'leader' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can promote to leader' }, 403);
    }

    await env.DB.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?')
      .bind(body.role, teamId, body.userId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/kick — kick member (leader/officer only)
  const kickMatch = path.match(/^\/api\/teams\/([^/]+)\/kick$/);
  if (kickMatch && request.method === 'POST') {
    const teamId = kickMatch[1];
    const body = await request.json();

    const myRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!myRole || (myRole.role !== 'leader' && myRole.role !== 'officer')) {
      return json({ error: 'No permission' }, 403);
    }

    // Can't kick leader
    const targetRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, body.userId).first();
    if (targetRole?.role === 'leader') return json({ error: "Can't kick the leader" }, 403);
    if (targetRole?.role === 'officer' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can kick officers' }, 403);
    }

    await env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, body.userId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/leave — leave team
  const leaveMatch = path.match(/^\/api\/teams\/([^/]+)\/leave$/);
  if (leaveMatch && request.method === 'POST') {
    const teamId = leaveMatch[1];

    const team = await env.DB.prepare('SELECT owner_id FROM teams WHERE id = ?').bind(teamId).first();
    if (team?.owner_id === user.userId) {
      return json({ error: 'Leader cannot leave. Delete the team or transfer ownership.' }, 400);
    }

    await env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, user.userId).run();
    return json({ ok: true });
  }

  // POST /api/invite/:code — join team via invite code
  const inviteMatch = path.match(/^\/api\/invite\/([^/]+)$/);
  if (inviteMatch && request.method === 'POST') {
    const code = inviteMatch[1];

    const team = await env.DB.prepare('SELECT * FROM teams WHERE invite_code = ?').bind(code).first();
    if (!team) return json({ error: 'Invalid invite code' }, 404);

    // Check if already a member
    const existing = await env.DB.prepare(
      'SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(team.id, user.userId).first();
    if (existing) return json({ error: 'Already a member', team: { id: team.id, name: team.name } }, 400);

    // Check member limit (premium owner = 50 members, free = 5)
    const owner = await env.DB.prepare('SELECT premium FROM users WHERE id = ?').bind(team.owner_id).first();
    const maxMembers = owner?.premium ? 50 : 5;
    const count = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM team_members WHERE team_id = ?'
    ).bind(team.id).first();
    if (count.count >= maxMembers) {
      return json({ error: `Team is full (${maxMembers} members max)` }, 403);
    }

    await env.DB.prepare('INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)')
      .bind(team.id, user.userId, 'member').run();

    return json({ ok: true, team: { id: team.id, name: team.name } });
  }

  // GET /api/invite/:code — get invite info (public)
  if (inviteMatch && request.method === 'GET') {
    const code = inviteMatch[1];
    const team = await env.DB.prepare('SELECT id, name FROM teams WHERE invite_code = ?').bind(code).first();
    if (!team) return json({ error: 'Invalid invite code' }, 404);
    const count = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM team_members WHERE team_id = ?'
    ).bind(team.id).first();
    return json({ team: { name: team.name, members: count.count } });
  }

  // === BOSS TIMER ROUTES ===

  // Helper: check team membership
  async function requireTeamMember(teamId, userId) {
    return env.DB.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, userId).first();
  }

  // GET /api/teams/:id/bosses
  const bossListMatch = path.match(/^\/api\/teams\/([^/]+)\/bosses$/);
  if (bossListMatch && request.method === 'GET') {
    const teamId = bossListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const bosses = await env.DB.prepare('SELECT * FROM bosses WHERE team_id = ? ORDER BY next_spawn ASC')
      .bind(teamId).all();
    return json({ bosses: bosses.results });
  }

  // POST /api/teams/:id/bosses — add boss
  if (bossListMatch && request.method === 'POST') {
    const teamId = bossListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (member.role === 'member') {
      // Members can add bosses too — officers+ can delete
    }

    const body = await request.json();
    if (!body.name?.trim()) return json({ error: 'Name required' }, 400);

    const settings = await env.DB.prepare('SELECT timezone FROM team_settings WHERE team_id = ?').bind(teamId).first();
    const tz = settings?.timezone || 'Asia/Manila';

    const id = crypto.randomUUID();
    let nextSpawn = Date.now() + 3600000; // default 1hr

    if (body.type === 'interval') {
      nextSpawn = Date.now() + (body.intervalMs || 3600000);
    } else if (body.type === 'fixed') {
      nextSpawn = getNextFixedSpawn(body.fixedTime, tz);
    } else if (body.type === 'weekly') {
      nextSpawn = getNextWeeklySpawn(body.weeklyDay, body.weeklyTime, tz);
    } else if (body.type === 'biweekly') {
      nextSpawn = getNextBiweeklySpawn(body.biweeklyDays, tz);
    }

    // Suppress immediate warning if inside alert window
    const alertMs = (body.alertMinutes || 5) * 60000;
    const warned = (nextSpawn - Date.now()) <= alertMs ? 1 : 0;

    await env.DB.prepare(`INSERT INTO bosses (id, team_id, name, type, interval_ms, fixed_time, weekly_day, weekly_time, biweekly_days, alert_minutes, next_spawn, warned) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, teamId, body.name.trim(), body.type,
        body.intervalMs || null, body.fixedTime || null,
        body.weeklyDay ?? null, body.weeklyTime || null,
        body.biweeklyDays ? JSON.stringify(body.biweeklyDays) : null,
        body.alertMinutes || 5, nextSpawn, warned).run();

    return json({ ok: true, id });
  }

  // POST /api/teams/:id/bosses/:bossId/kill
  const bossKillMatch = path.match(/^\/api\/teams\/([^/]+)\/bosses\/([^/]+)\/kill$/);
  if (bossKillMatch && request.method === 'POST') {
    const [, teamId, bossId] = bossKillMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json().catch(() => ({}));
    const deathTime = body.deathTime || Date.now();

    const boss = await env.DB.prepare('SELECT * FROM bosses WHERE id = ? AND team_id = ?').bind(bossId, teamId).first();
    if (!boss) return json({ error: 'Boss not found' }, 404);

    const settings = await env.DB.prepare('SELECT timezone FROM team_settings WHERE team_id = ?').bind(teamId).first();
    const tz = settings?.timezone || 'Asia/Manila';
    const nextSpawn = calcNextSpawn(boss, deathTime, tz);

    await env.DB.prepare('UPDATE bosses SET status = ?, spawned_at = NULL, auto_reset_at = NULL, last_death = ?, next_spawn = ?, warned = 0, spawn_notified = 0 WHERE id = ?')
      .bind('waiting', deathTime, nextSpawn, bossId).run();

    return json({ ok: true });
  }

  // DELETE /api/teams/:id/bosses/:bossId
  const bossDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/bosses\/([^/]+)$/);
  if (bossDeleteMatch && request.method === 'DELETE') {
    const [, teamId, bossId] = bossDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    await env.DB.prepare('DELETE FROM bosses WHERE id = ? AND team_id = ?').bind(bossId, teamId).run();
    return json({ ok: true });
  }

  // GET /api/teams/:id/settings
  const settingsGetMatch = path.match(/^\/api\/teams\/([^/]+)\/settings$/);
  if (settingsGetMatch && request.method === 'GET') {
    const teamId = settingsGetMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    return json({
      webhookUrl: settings?.webhook_url ? '...' + settings.webhook_url.slice(-8) : '',
      onWarning: settings?.on_warning ?? true,
      onSpawn: settings?.on_spawn ?? true,
      timezone: settings?.timezone || 'Asia/Manila',
    });
  }

  // PUT /api/teams/:id/settings
  if (settingsGetMatch && request.method === 'PUT') {
    const teamId = settingsGetMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) {
      return json({ error: 'Officers+ only' }, 403);
    }

    const body = await request.json();
    const existing = await env.DB.prepare('SELECT 1 FROM team_settings WHERE team_id = ?').bind(teamId).first();

    if (existing) {
      const sets = [];
      const vals = [];
      if (body.webhookUrl !== undefined) { sets.push('webhook_url = ?'); vals.push(body.webhookUrl); }
      if (body.onWarning !== undefined) { sets.push('on_warning = ?'); vals.push(body.onWarning ? 1 : 0); }
      if (body.onSpawn !== undefined) { sets.push('on_spawn = ?'); vals.push(body.onSpawn ? 1 : 0); }
      if (body.timezone !== undefined) { sets.push('timezone = ?'); vals.push(body.timezone); }
      if (sets.length > 0) {
        vals.push(teamId);
        await env.DB.prepare(`UPDATE team_settings SET ${sets.join(', ')} WHERE team_id = ?`).bind(...vals).run();
      }
    } else {
      await env.DB.prepare('INSERT INTO team_settings (team_id, webhook_url, on_warning, on_spawn, timezone) VALUES (?, ?, ?, ?, ?)')
        .bind(teamId, body.webhookUrl || null, body.onWarning !== false ? 1 : 0, body.onSpawn !== false ? 1 : 0, body.timezone || 'Asia/Manila').run();
    }

    return json({ ok: true });
  }

  // POST /api/teams/:id/settings/test — test webhook
  const settingsTestMatch = path.match(/^\/api\/teams\/([^/]+)\/settings\/test$/);
  if (settingsTestMatch && request.method === 'POST') {
    const teamId = settingsTestMatch[1];
    const settings = await env.DB.prepare('SELECT webhook_url FROM team_settings WHERE team_id = ?').bind(teamId).first();
    if (!settings?.webhook_url) return json({ error: 'No webhook' }, 400);
    await sendDiscord(settings.webhook_url, 'Test Notification', 'Guild Manager webhook is working!', 5793266);
    return json({ ok: true });
  }

  // === EVENT ROUTES ===

  // GET /api/teams/:id/events
  const eventListMatch = path.match(/^\/api\/teams\/([^/]+)\/events$/);
  if (eventListMatch && request.method === 'GET') {
    const teamId = eventListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const events = await env.DB.prepare(`
      SELECT e.*, u.username as creator_name,
        (SELECT COUNT(*) FROM event_rsvps WHERE event_id = e.id AND status = 'going') as going_count,
        (SELECT COUNT(*) FROM event_rsvps WHERE event_id = e.id AND status = 'maybe') as maybe_count,
        (SELECT COUNT(*) FROM event_rsvps WHERE event_id = e.id AND status = 'not_going') as not_going_count,
        (SELECT status FROM event_rsvps WHERE event_id = e.id AND user_id = ?) as my_rsvp
      FROM events e
      JOIN users u ON u.id = e.created_by
      WHERE e.team_id = ?
      ORDER BY e.event_time ASC
    `).bind(user.userId, teamId).all();

    return json({ events: events.results });
  }

  // POST /api/teams/:id/events — create event
  if (eventListMatch && request.method === 'POST') {
    const teamId = eventListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json();
    if (!body.title?.trim() || !body.eventTime) return json({ error: 'Title and time required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO events (id, team_id, title, description, event_type, event_time, duration_minutes, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, teamId, body.title.trim(), body.description || null, body.eventType || 'other',
        body.eventTime, body.durationMinutes || 60, user.userId).run();

    // Auto-RSVP creator as going
    await env.DB.prepare('INSERT INTO event_rsvps (event_id, user_id, status) VALUES (?, ?, ?)')
      .bind(id, user.userId, 'going').run();

    // Discord notification
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    if (settings?.webhook_url) {
      const date = new Date(body.eventTime).toLocaleString('en-US', { timeZone: settings.timezone || 'Asia/Manila' });
      await sendDiscord(settings.webhook_url, `New Event: ${body.title}`,
        `**${body.title}** scheduled for **${date}**\nCreated by ${user.username}${body.description ? '\n\n' + body.description : ''}`,
        5793266);
    }

    return json({ ok: true, id });
  }

  // DELETE /api/teams/:id/events/:eventId
  const eventDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/events\/([^/]+)$/);
  if (eventDeleteMatch && request.method === 'DELETE') {
    const [, teamId, eventId] = eventDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const event = await env.DB.prepare('SELECT * FROM events WHERE id = ? AND team_id = ?').bind(eventId, teamId).first();
    if (!event) return json({ error: 'Not found' }, 404);

    // Creator, officers, or leader can delete
    if (event.created_by !== user.userId && member.role === 'member') {
      return json({ error: 'No permission' }, 403);
    }

    await env.DB.batch([
      env.DB.prepare('DELETE FROM event_rsvps WHERE event_id = ?').bind(eventId),
      env.DB.prepare('DELETE FROM event_attendance WHERE event_id = ?').bind(eventId),
      env.DB.prepare('DELETE FROM events WHERE id = ?').bind(eventId),
    ]);
    return json({ ok: true });
  }

  // POST /api/teams/:id/events/:eventId/rsvp
  const rsvpMatch = path.match(/^\/api\/teams\/([^/]+)\/events\/([^/]+)\/rsvp$/);
  if (rsvpMatch && request.method === 'POST') {
    const [, teamId, eventId] = rsvpMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json();
    const status = ['going', 'maybe', 'not_going'].includes(body.status) ? body.status : 'going';

    const existing = await env.DB.prepare('SELECT 1 FROM event_rsvps WHERE event_id = ? AND user_id = ?')
      .bind(eventId, user.userId).first();

    if (existing) {
      await env.DB.prepare('UPDATE event_rsvps SET status = ?, responded_at = ? WHERE event_id = ? AND user_id = ?')
        .bind(status, Math.floor(Date.now() / 1000), eventId, user.userId).run();
    } else {
      await env.DB.prepare('INSERT INTO event_rsvps (event_id, user_id, status) VALUES (?, ?, ?)')
        .bind(eventId, user.userId, status).run();
    }

    return json({ ok: true });
  }

  // GET /api/teams/:id/events/:eventId/rsvps — get RSVP details
  const rsvpListMatch = path.match(/^\/api\/teams\/([^/]+)\/events\/([^/]+)\/rsvps$/);
  if (rsvpListMatch && request.method === 'GET') {
    const [, teamId, eventId] = rsvpListMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const rsvps = await env.DB.prepare(`
      SELECT u.username, u.avatar, u.discord_id, r.status
      FROM event_rsvps r JOIN users u ON u.id = r.user_id
      WHERE r.event_id = ? ORDER BY r.responded_at ASC
    `).bind(eventId).all();

    return json({ rsvps: rsvps.results });
  }

  // POST /api/teams/:id/events/:eventId/attendance — mark attendance (officers+)
  const attendMatch = path.match(/^\/api\/teams\/([^/]+)\/events\/([^/]+)\/attendance$/);
  if (attendMatch && request.method === 'POST') {
    const [, teamId, eventId] = attendMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    // body.attendance = [{userId, attended: true/false}, ...]
    for (const a of (body.attendance || [])) {
      const existing = await env.DB.prepare('SELECT 1 FROM event_attendance WHERE event_id = ? AND user_id = ?')
        .bind(eventId, a.userId).first();
      if (existing) {
        await env.DB.prepare('UPDATE event_attendance SET attended = ? WHERE event_id = ? AND user_id = ?')
          .bind(a.attended ? 1 : 0, eventId, a.userId).run();
      } else {
        await env.DB.prepare('INSERT INTO event_attendance (event_id, user_id, attended) VALUES (?, ?, ?)')
          .bind(eventId, a.userId, a.attended ? 1 : 0).run();
      }
    }
    return json({ ok: true });
  }

  // GET /api/teams/:id/events/:eventId/attendance
  if (attendMatch && request.method === 'GET') {
    const [, teamId, eventId] = attendMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const attendance = await env.DB.prepare(`
      SELECT u.username, u.avatar, u.discord_id, a.attended
      FROM event_attendance a JOIN users u ON u.id = a.user_id
      WHERE a.event_id = ?
    `).bind(eventId).all();

    return json({ attendance: attendance.results });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },
};
