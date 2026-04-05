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
    'Access-Control-Allow-Origin': 'https://anomaly-surround.github.io',
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
      on_announcement INTEGER DEFAULT 1,
      timezone TEXT DEFAULT 'Asia/Manila',
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      pinned INTEGER DEFAULT 0,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS member_activity (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      last_seen INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_loot (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      boss_id TEXT,
      boss_name TEXT NOT NULL,
      item_name TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      dkp_cost INTEGER DEFAULT 0,
      noted_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (recipient_id) REFERENCES users(id),
      FOREIGN KEY (noted_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_ledger (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS member_availability (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      day INTEGER NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      PRIMARY KEY (team_id, user_id, day, start_time),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
  ]);
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS member_notes (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      target_user_id TEXT NOT NULL,
      author_id TEXT NOT NULL,
      note TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (target_user_id) REFERENCES users(id),
      FOREIGN KEY (author_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS chat_reactions (
      message_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      emoji TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (message_id, user_id, emoji),
      FOREIGN KEY (message_id) REFERENCES chat_messages(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_kill_log (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      boss_id TEXT NOT NULL,
      boss_name TEXT NOT NULL,
      killed_at INTEGER NOT NULL,
      killed_by TEXT,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      game TEXT NOT NULL,
      bosses TEXT NOT NULL,
      is_global INTEGER DEFAULT 0,
      created_by TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_templates (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      event_type TEXT DEFAULT 'other',
      duration_minutes INTEGER DEFAULT 60,
      recurrence TEXT,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS loot_wishlist (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      item_name TEXT NOT NULL,
      boss_name TEXT,
      priority INTEGER DEFAULT 1,
      fulfilled INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_auctions (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      item_name TEXT NOT NULL,
      boss_name TEXT,
      started_by TEXT NOT NULL,
      status TEXT DEFAULT 'open',
      min_bid INTEGER DEFAULT 0,
      winner_id TEXT,
      winning_bid INTEGER,
      expires_at INTEGER,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_bids (
      id TEXT PRIMARY KEY,
      auction_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (auction_id) REFERENCES dkp_auctions(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS analytics_snapshots (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      snapshot_type TEXT NOT NULL,
      snapshot_data TEXT NOT NULL,
      snapshot_date INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS custom_roles (
      team_id TEXT NOT NULL,
      base_role TEXT NOT NULL,
      display_name TEXT NOT NULL,
      color TEXT,
      PRIMARY KEY (team_id, base_role),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS war_log (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      opponent TEXT NOT NULL,
      result TEXT NOT NULL,
      event_type TEXT DEFAULT 'gvg',
      score_us INTEGER,
      score_them INTEGER,
      notes TEXT,
      war_date INTEGER DEFAULT (unixepoch()),
      logged_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (logged_by) REFERENCES users(id)
    )`),
  ]);

  // Phase 10 tables: Polls, Roster, Performance, Recruitment
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS polls (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      question TEXT NOT NULL,
      poll_type TEXT DEFAULT 'single',
      created_by TEXT NOT NULL,
      closed INTEGER DEFAULT 0,
      expires_at INTEGER,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS poll_options (
      id TEXT PRIMARY KEY,
      poll_id TEXT NOT NULL,
      label TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0,
      FOREIGN KEY (poll_id) REFERENCES polls(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id TEXT NOT NULL,
      option_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (poll_id, option_id, user_id),
      FOREIGN KEY (poll_id) REFERENCES polls(id),
      FOREIGN KEY (option_id) REFERENCES poll_options(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS rosters (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      event_id TEXT,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS roster_slots (
      id TEXT PRIMARY KEY,
      roster_id TEXT NOT NULL,
      role_name TEXT NOT NULL,
      user_id TEXT,
      sort_order INTEGER DEFAULT 0,
      FOREIGN KEY (roster_id) REFERENCES rosters(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS performance_entries (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      event_label TEXT NOT NULL,
      stat_name TEXT NOT NULL,
      stat_value REAL NOT NULL,
      logged_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (logged_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS recruitment_posts (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      role_needed TEXT,
      status TEXT DEFAULT 'open',
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS recruitment_applications (
      id TEXT PRIMARY KEY,
      post_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by TEXT,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (post_id) REFERENCES recruitment_posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
  ]);

  // Run migrations (each one is idempotent via catch)
  const needsMigrations = await db.prepare("SELECT premium FROM users LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT accent_color FROM team_settings LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT trial_started FROM users LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT google_id FROM users LIMIT 1").first().then(() => false).catch(() => true);
  if (needsMigrations) {
    const migrations = [
      'ALTER TABLE users ADD COLUMN premium INTEGER DEFAULT 0',
      'ALTER TABLE users ADD COLUMN premium_type TEXT',
      'ALTER TABLE users ADD COLUMN premium_until INTEGER',
      'ALTER TABLE users ADD COLUMN ls_customer_id TEXT',
      'ALTER TABLE team_settings ADD COLUMN on_announcement INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN on_event INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN on_war INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN event_reminder_minutes INTEGER DEFAULT 15',
      'ALTER TABLE team_settings ADD COLUMN inactive_days INTEGER DEFAULT 7',
      'ALTER TABLE team_settings ADD COLUMN default_event_duration INTEGER DEFAULT 60',
      'ALTER TABLE team_settings ADD COLUMN team_description TEXT',
      'ALTER TABLE team_settings ADD COLUMN members_create_events INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN auto_delete_events_days INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN auto_delete_chat_days INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN starting_dkp INTEGER DEFAULT 0',
      'ALTER TABLE events ADD COLUMN recurrence TEXT',
      'ALTER TABLE events ADD COLUMN parent_event_id TEXT',
      'ALTER TABLE events ADD COLUMN end_notified INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN webhook_boss TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_events TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_wars TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_announcements TEXT',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_enabled INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_percent INTEGER DEFAULT 10',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_inactive_days INTEGER DEFAULT 14',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_interval_days INTEGER DEFAULT 7',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_last_run INTEGER',
      'ALTER TABLE team_settings ADD COLUMN accent_color TEXT',
      'ALTER TABLE team_settings ADD COLUMN team_icon TEXT',
      'ALTER TABLE users ADD COLUMN trial_started INTEGER',
      'ALTER TABLE users ADD COLUMN trial_used INTEGER DEFAULT 0',
      'ALTER TABLE users ADD COLUMN google_id TEXT',
      'ALTER TABLE users ADD COLUMN auth_type TEXT DEFAULT "discord"',
    ];
    for (const sql of migrations) await db.exec(sql).catch(() => {});
  }
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
  try { await initDB(env.DB); } catch(e) { console.error('initDB error in cron:', e); }
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

  // Event reminders (configurable minutes before)
  const upcomingEvents = await env.DB.prepare(
    'SELECT e.*, ts.event_reminder_minutes FROM events e LEFT JOIN team_settings ts ON ts.team_id = e.team_id WHERE e.event_time > ? AND e.event_time <= ? + COALESCE(ts.event_reminder_minutes, 15) * 60000 AND e.reminder_sent = 0'
  ).bind(now, now).all().catch(() => ({ results: [] }));

  for (const event of upcomingEvents.results) {
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(event.team_id).first();
    if (settings?.webhook_url && settings?.on_event !== 0) {
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

  // Event end notifications
  const endedEvents = await env.DB.prepare(
    'SELECT * FROM events WHERE event_time + duration_minutes * 60000 <= ? AND start_notified = 1 AND end_notified = 0'
  ).bind(now).all().catch(() => ({ results: [] }));

  for (const event of endedEvents.results) {
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(event.team_id).first();
    if (settings?.webhook_url) {
      await sendDiscord(settings.webhook_url, `${event.title} has ended!`,
        `**${event.title}** has ended. Thanks to everyone who participated!`, 5763719);
    }
    await env.DB.prepare('UPDATE events SET end_notified = 1 WHERE id = ?').bind(event.id).run();
  }

  // Auto-create next recurring event after one ends
  const recurringEnded = await env.DB.prepare(
    "SELECT * FROM events WHERE recurrence IS NOT NULL AND recurrence != 'none' AND event_time + duration_minutes * 60000 <= ? AND end_notified = 1"
  ).bind(now).all().catch(() => ({ results: [] }));

  for (const event of recurringEnded.results) {
    // Check if next occurrence already exists
    const parentId = event.parent_event_id || event.id;
    const existing = await env.DB.prepare(
      'SELECT 1 FROM events WHERE parent_event_id = ? AND event_time > ?'
    ).bind(parentId, event.event_time).first();
    if (existing) continue;

    let nextTime = event.event_time;
    if (event.recurrence === 'daily') nextTime += 86400000;
    else if (event.recurrence === 'weekly') nextTime += 7 * 86400000;
    else if (event.recurrence === 'biweekly') nextTime += 14 * 86400000;
    else if (event.recurrence === 'monthly') {
      const d = new Date(event.event_time);
      d.setMonth(d.getMonth() + 1);
      nextTime = d.getTime();
    }
    // Skip if next time is too far past (stale)
    if (nextTime < now - 86400000) continue;

    const newId = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO events (id, team_id, title, description, event_type, event_time, duration_minutes, created_by, recurrence, parent_event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(newId, event.team_id, event.title, event.description, event.event_type, nextTime, event.duration_minutes, event.created_by, event.recurrence, parentId).run();
  }

  // DKP decay for premium teams
  const decayTeams = await env.DB.prepare(
    'SELECT ts.* FROM team_settings ts JOIN teams t ON t.id = ts.team_id JOIN users u ON u.id = t.owner_id WHERE ts.dkp_decay_enabled = 1 AND u.premium = 1 AND (ts.dkp_decay_last_run IS NULL OR ts.dkp_decay_last_run < unixepoch() - ts.dkp_decay_interval_days * 86400)'
  ).all().catch(() => ({ results: [] }));

  for (const ts of decayTeams.results) {
    const inactiveMembers = await env.DB.prepare(
      'SELECT ma.user_id FROM member_activity ma WHERE ma.team_id = ? AND ma.last_seen < unixepoch() - ?'
    ).bind(ts.team_id, (ts.dkp_decay_inactive_days || 14) * 86400).all();

    for (const m of inactiveMembers.results) {
      const bal = await env.DB.prepare('SELECT COALESCE(SUM(amount),0) as balance FROM dkp_ledger WHERE team_id = ? AND user_id = ?')
        .bind(ts.team_id, m.user_id).first();
      if (bal.balance > 0) {
        const decay = Math.max(1, Math.floor(bal.balance * (ts.dkp_decay_percent || 10) / 100));
        await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
          .bind(crypto.randomUUID(), ts.team_id, m.user_id, -decay, 'Inactivity decay', 'system').run();
      }
    }
    await env.DB.prepare('UPDATE team_settings SET dkp_decay_last_run = unixepoch() WHERE team_id = ?').bind(ts.team_id).run();
  }

  // Auto-close expired auctions
  const expiredAuctions = await env.DB.prepare("SELECT * FROM dkp_auctions WHERE status = 'open' AND expires_at IS NOT NULL AND expires_at < ?")
    .bind(Math.floor(now / 1000)).all().catch(() => ({ results: [] }));

  for (const auction of expiredAuctions.results) {
    const topBid = await env.DB.prepare('SELECT * FROM dkp_bids WHERE auction_id = ? ORDER BY amount DESC LIMIT 1').bind(auction.id).first();
    if (topBid) {
      await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), auction.team_id, topBid.user_id, -topBid.amount, `Auction: ${auction.item_name}`, 'system').run();
      await env.DB.prepare('UPDATE dkp_auctions SET status = ?, winner_id = ?, winning_bid = ? WHERE id = ?')
        .bind('closed', topBid.user_id, topBid.amount, auction.id).run();
    } else {
      await env.DB.prepare("UPDATE dkp_auctions SET status = 'closed' WHERE id = ?").bind(auction.id).run();
    }
  }

  // Auto-delete old events and chat (per team settings)
  const allSettings = await env.DB.prepare('SELECT * FROM team_settings WHERE auto_delete_events_days > 0 OR auto_delete_chat_days > 0').all().catch(() => ({ results: [] }));
  for (const s of allSettings.results) {
    if (s.auto_delete_events_days > 0) {
      const cutoff = Math.floor(now / 1000) - s.auto_delete_events_days * 86400;
      const oldEvents = await env.DB.prepare('SELECT id FROM events WHERE team_id = ? AND event_time / 1000 < ? AND recurrence IS NULL').bind(s.team_id, cutoff).all();
      for (const e of oldEvents.results) {
        await env.DB.batch([
          env.DB.prepare('DELETE FROM event_rsvps WHERE event_id = ?').bind(e.id),
          env.DB.prepare('DELETE FROM event_attendance WHERE event_id = ?').bind(e.id),
          env.DB.prepare('DELETE FROM events WHERE id = ?').bind(e.id),
        ]);
      }
    }
    if (s.auto_delete_chat_days > 0) {
      const cutoff = Math.floor(now / 1000) - s.auto_delete_chat_days * 86400;
      await env.DB.prepare('DELETE FROM chat_messages WHERE team_id = ? AND created_at < ?').bind(s.team_id, cutoff).run();
    }
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
  try { await initDB(env.DB); } catch(e) { console.error('initDB error:', e); }

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

  // GET /auth/google — redirect to Google OAuth
  if (path === '/auth/google') {
    const redirect = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/google/callback')}&response_type=code&scope=openid%20profile&prompt=select_account`;
    return Response.redirect(redirect, 302);
  }

  // GET /auth/google/callback
  if (path === '/auth/google/callback') {
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    const frontendUrl = 'https://anomaly-surround.github.io/guild-manager';
    if (error || !code) return Response.redirect(frontendUrl, 302);

    try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: url.origin + '/auth/google/callback',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return Response.redirect(frontendUrl, 302);

    const userRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const googleUser = await userRes.json();
    if (!googleUser.id) return json({ error: 'Failed to get Google user' }, 400);

    const existing = await env.DB.prepare('SELECT id FROM users WHERE google_id = ?').bind(googleUser.id).first();
    let finalUserId;

    if (existing) {
      finalUserId = existing.id;
      await env.DB.prepare('UPDATE users SET username = ?, avatar = ? WHERE id = ?')
        .bind(googleUser.name || googleUser.email, googleUser.picture || null, existing.id).run();
    } else {
      finalUserId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO users (id, google_id, discord_id, username, avatar, auth_type) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(finalUserId, googleUser.id, 'google_' + googleUser.id, googleUser.name || googleUser.email, googleUser.picture || null, 'google').run();
    }

    const jwt = await createToken({ userId: finalUserId, username: googleUser.name || googleUser.email }, env.JWT_SECRET);
    return Response.redirect(`${frontendUrl}?token=${jwt}`, 302);
    } catch(e) {
      console.error('Google auth error:', e);
      return Response.redirect(frontendUrl, 302);
    }
  }

  // POST /auth/guest — create guest account
  if (path === '/auth/guest' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const username = body.username?.trim();
    if (!username || username.length < 2 || username.length > 20 || !/^[a-zA-Z0-9_\- ]+$/.test(username)) {
      return json({ error: 'Username must be 2-20 characters (letters, numbers, underscore, dash)' }, 400);
    }

    const userId = crypto.randomUUID();
    const guestId = 'guest_' + userId.slice(0, 8);

    await env.DB.prepare('INSERT INTO users (id, discord_id, username, auth_type) VALUES (?, ?, ?, ?)')
      .bind(userId, guestId, username, 'guest').run();

    const jwt = await createToken({ userId, username }, env.JWT_SECRET);
    return json({ token: jwt });
  }

  // GET /auth/me — get current user
  if (path === '/auth/me') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) return json({ error: 'User not found' }, 404);
    // Check if subscription is still active
    let isPremium = false;
    let isTrial = false;
    let trialDaysLeft = 0;
    if (dbUser.premium) {
      if (String(dbUser.premium_type).trim().toLowerCase() === 'lifetime') {
        isPremium = true;
      } else if (dbUser.premium_until && dbUser.premium_until > Math.floor(Date.now() / 1000)) {
        isPremium = true;
      } else if (!dbUser.premium_type && !dbUser.premium_until) {
        isPremium = true;
      } else {
        await env.DB.prepare('UPDATE users SET premium = 0 WHERE id = ?').bind(dbUser.id).run();
      }
    }

    // Check free trial
    if (!isPremium && dbUser.trial_started) {
      const trialEnd = dbUser.trial_started + 7 * 86400;
      const nowSec = Math.floor(Date.now() / 1000);
      if (nowSec < trialEnd) {
        isPremium = true;
        isTrial = true;
        trialDaysLeft = Math.ceil((trialEnd - nowSec) / 86400);
      } else if (!dbUser.trial_used) {
        await env.DB.prepare('UPDATE users SET trial_used = 1 WHERE id = ?').bind(dbUser.id).run();
      }
    }

    return json({
      id: dbUser.id,
      username: dbUser.username,
      avatar: dbUser.avatar,
      discordId: dbUser.discord_id,
      premium: isPremium,
      premiumType: isPremium ? (isTrial ? 'trial' : dbUser.premium_type) : null,
      trial: isTrial,
      trialDaysLeft: isTrial ? trialDaysLeft : 0,
      trialUsed: !!(dbUser.trial_used || dbUser.trial_started),
      authType: dbUser.auth_type || 'discord',
    });
  }

  // --- LemonSqueezy webhook (no auth required) ---
  if (path === '/ls/webhook' && request.method === 'POST') {
    // Verify webhook signature
    const rawBody = await request.text();
    const signature = request.headers.get('x-signature');
    if (env.LS_WEBHOOK_SECRET && signature) {
      const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.LS_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(rawBody)))));
      if (sig !== signature) return json({ error: 'Invalid signature' }, 403);
    }
    const body = JSON.parse(rawBody);
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
  // POST /api/start-trial — start 7-day free trial
  if (path === '/api/start-trial' && request.method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) return json({ error: 'User not found' }, 404);
    if (dbUser.auth_type === 'guest') return json({ error: 'Sign in with Discord or Google to start a trial' }, 400);
    if (dbUser.premium) return json({ error: 'Already premium' }, 400);
    if (dbUser.trial_started || dbUser.trial_used) return json({ error: 'Trial already used' }, 400);

    await env.DB.prepare('UPDATE users SET trial_started = ? WHERE id = ?')
      .bind(Math.floor(Date.now() / 1000), user.userId).run();

    return json({ ok: true, trialDaysLeft: 7 });
  }

  if (path === '/api/checkout' && request.method === 'POST') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);

    const body = await request.json();
    const variant = body.type === 'lifetime' ? env.LS_MONTHLY_VARIANT : env.LS_LIFETIME_VARIANT;

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
        (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count,
        (SELECT COUNT(*) FROM member_activity WHERE team_id = t.id AND last_seen > unixepoch() - 300) as online_count,
        (SELECT team_description FROM team_settings WHERE team_id = t.id) as description,
        (SELECT team_icon FROM team_settings WHERE team_id = t.id) as team_icon,
        (SELECT COUNT(*) FROM events WHERE team_id = t.id AND event_time > ? AND event_time <= ? + 86400000) as upcoming_events_24h
      FROM teams t
      JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
      ORDER BY t.created_at DESC
    `).bind(Date.now(), Date.now(), user.userId).all();
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

    // Track activity
    await env.DB.prepare('INSERT OR REPLACE INTO member_activity (team_id, user_id, last_seen) VALUES (?, ?, unixepoch())')
      .bind(teamId, user.userId).run();

    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(teamId).first();
    if (!team) return json({ error: 'Team not found' }, 404);

    // Check if team owner is premium (including trial)
    const premiumTeam = await isPremiumTeam(teamId);

    const members = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar, u.discord_id, u.premium, tm.role, tm.joined_at,
        ma.last_seen
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      LEFT JOIN member_activity ma ON ma.team_id = tm.team_id AND ma.user_id = tm.user_id
      WHERE tm.team_id = ?
      ORDER BY
        CASE tm.role WHEN 'leader' THEN 0 WHEN 'officer' THEN 1 ELSE 2 END,
        tm.joined_at ASC
    `).bind(teamId).all();

    return json({
      team: { ...team, my_role: membership.role, premium_team: premiumTeam },
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

    // Delete all child records first
    // Get event IDs for this team to clean up rsvps/attendance/reactions
    const teamEvents = await env.DB.prepare('SELECT id FROM events WHERE team_id = ?').bind(teamId).all();
    for (const e of teamEvents.results) {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM event_rsvps WHERE event_id = ?').bind(e.id),
        env.DB.prepare('DELETE FROM event_attendance WHERE event_id = ?').bind(e.id),
      ]);
    }
    // Get chat message IDs to clean up reactions
    const chatMsgs = await env.DB.prepare('SELECT id FROM chat_messages WHERE team_id = ?').bind(teamId).all();
    for (const m of chatMsgs.results) {
      await env.DB.prepare('DELETE FROM chat_reactions WHERE message_id = ?').bind(m.id).run();
    }
    // Get auction IDs to clean up bids
    const auctions = await env.DB.prepare('SELECT id FROM dkp_auctions WHERE team_id = ?').bind(teamId).all();
    for (const a of auctions.results) {
      await env.DB.prepare('DELETE FROM dkp_bids WHERE auction_id = ?').bind(a.id).run();
    }
    // Delete everything else
    await env.DB.batch([
      env.DB.prepare('DELETE FROM events WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM bosses WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM member_notes WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM member_activity WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM member_availability WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM boss_loot WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM boss_kill_log WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM dkp_ledger WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM dkp_auctions WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM loot_wishlist WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM chat_messages WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM war_log WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM announcements WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM event_templates WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM analytics_snapshots WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM custom_roles WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM team_settings WHERE team_id = ?').bind(teamId),
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

    await env.DB.batch([
      env.DB.prepare('DELETE FROM member_notes WHERE team_id = ? AND target_user_id = ?').bind(teamId, body.userId),
      env.DB.prepare('DELETE FROM member_activity WHERE team_id = ? AND user_id = ?').bind(teamId, body.userId),
      env.DB.prepare('DELETE FROM member_availability WHERE team_id = ? AND user_id = ?').bind(teamId, body.userId),
      env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').bind(teamId, body.userId),
    ]);
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

    await env.DB.batch([
      env.DB.prepare('DELETE FROM member_notes WHERE team_id = ? AND target_user_id = ?').bind(teamId, user.userId),
      env.DB.prepare('DELETE FROM member_activity WHERE team_id = ? AND user_id = ?').bind(teamId, user.userId),
      env.DB.prepare('DELETE FROM member_availability WHERE team_id = ? AND user_id = ?').bind(teamId, user.userId),
      env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?').bind(teamId, user.userId),
    ]);
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

  function getWebhook(settings, channel) {
    const specific = settings?.['webhook_' + channel];
    return specific || settings?.webhook_url || null;
  }

  async function isPremiumTeam(teamId) {
    try {
      const team = await env.DB.prepare('SELECT owner_id FROM teams WHERE id = ?').bind(teamId).first();
      if (!team) return false;
      const owner = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(team.owner_id).first();
      if (!owner) return false;
      if (owner.premium) {
        if (String(owner.premium_type || '').trim().toLowerCase() === 'lifetime') return true;
        if (owner.premium_until && owner.premium_until > Math.floor(Date.now() / 1000)) return true;
        if (!owner.premium_type && !owner.premium_until) return true;
      }
      if (owner.trial_started && !owner.trial_used) {
        const trialEnd = owner.trial_started + 7 * 86400;
        if (Math.floor(Date.now() / 1000) < trialEnd) return true;
      }
      return false;
    } catch(e) {
      console.error('isPremiumTeam error:', e);
      return false;
    }
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

    // Log kill for analytics
    await env.DB.prepare('INSERT INTO boss_kill_log (id, team_id, boss_id, boss_name, killed_at, killed_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), teamId, bossId, boss.name, deathTime, user.userId).run();

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
      onAnnouncement: settings?.on_announcement ?? true,
      onEvent: settings?.on_event ?? true,
      onWar: settings?.on_war ?? true,
      eventReminderMinutes: settings?.event_reminder_minutes ?? 15,
      inactiveDays: settings?.inactive_days ?? 7,
      defaultEventDuration: settings?.default_event_duration ?? 60,
      teamDescription: settings?.team_description || '',
      membersCreateEvents: settings?.members_create_events ?? true,
      autoDeleteEventsDays: settings?.auto_delete_events_days ?? 0,
      autoDeleteChatDays: settings?.auto_delete_chat_days ?? 0,
      startingDkp: settings?.starting_dkp ?? 0,
      timezone: settings?.timezone || 'Asia/Manila',
      // Premium settings
      webhookBoss: settings?.webhook_boss ? '...' + settings.webhook_boss.slice(-8) : '',
      webhookEvents: settings?.webhook_events ? '...' + settings.webhook_events.slice(-8) : '',
      webhookWars: settings?.webhook_wars ? '...' + settings.webhook_wars.slice(-8) : '',
      webhookAnnouncements: settings?.webhook_announcements ? '...' + settings.webhook_announcements.slice(-8) : '',
      dkpDecayEnabled: !!(settings?.dkp_decay_enabled),
      dkpDecayPercent: settings?.dkp_decay_percent ?? 10,
      dkpDecayInactiveDays: settings?.dkp_decay_inactive_days ?? 14,
      dkpDecayIntervalDays: settings?.dkp_decay_interval_days ?? 7,
      accentColor: settings?.accent_color || '',
      teamIcon: settings?.team_icon || '',
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
      if (body.webhookUrl !== undefined) {
        if (body.webhookUrl && !body.webhookUrl.startsWith('https://discord.com/api/webhooks/')) return json({ error: 'Webhook must be a Discord webhook URL' }, 400);
        sets.push('webhook_url = ?'); vals.push(body.webhookUrl);
      }
      if (body.onWarning !== undefined) { sets.push('on_warning = ?'); vals.push(body.onWarning ? 1 : 0); }
      if (body.onSpawn !== undefined) { sets.push('on_spawn = ?'); vals.push(body.onSpawn ? 1 : 0); }
      if (body.onAnnouncement !== undefined) { sets.push('on_announcement = ?'); vals.push(body.onAnnouncement ? 1 : 0); }
      if (body.onEvent !== undefined) { sets.push('on_event = ?'); vals.push(body.onEvent ? 1 : 0); }
      if (body.onWar !== undefined) { sets.push('on_war = ?'); vals.push(body.onWar ? 1 : 0); }
      if (body.eventReminderMinutes !== undefined) { sets.push('event_reminder_minutes = ?'); vals.push(body.eventReminderMinutes); }
      if (body.inactiveDays !== undefined) { sets.push('inactive_days = ?'); vals.push(body.inactiveDays); }
      if (body.defaultEventDuration !== undefined) { sets.push('default_event_duration = ?'); vals.push(body.defaultEventDuration); }
      if (body.teamDescription !== undefined) { sets.push('team_description = ?'); vals.push(body.teamDescription || null); }
      if (body.membersCreateEvents !== undefined) { sets.push('members_create_events = ?'); vals.push(body.membersCreateEvents ? 1 : 0); }
      if (body.autoDeleteEventsDays !== undefined) { sets.push('auto_delete_events_days = ?'); vals.push(body.autoDeleteEventsDays); }
      if (body.autoDeleteChatDays !== undefined) { sets.push('auto_delete_chat_days = ?'); vals.push(body.autoDeleteChatDays); }
      if (body.startingDkp !== undefined) { sets.push('starting_dkp = ?'); vals.push(body.startingDkp); }
      if (body.timezone !== undefined) { sets.push('timezone = ?'); vals.push(body.timezone); }
      // Premium fields
      if (body.webhookBoss !== undefined) { sets.push('webhook_boss = ?'); vals.push(body.webhookBoss || null); }
      if (body.webhookEvents !== undefined) { sets.push('webhook_events = ?'); vals.push(body.webhookEvents || null); }
      if (body.webhookWars !== undefined) { sets.push('webhook_wars = ?'); vals.push(body.webhookWars || null); }
      if (body.webhookAnnouncements !== undefined) { sets.push('webhook_announcements = ?'); vals.push(body.webhookAnnouncements || null); }
      if (body.dkpDecayEnabled !== undefined) { sets.push('dkp_decay_enabled = ?'); vals.push(body.dkpDecayEnabled ? 1 : 0); }
      if (body.dkpDecayPercent !== undefined) { sets.push('dkp_decay_percent = ?'); vals.push(body.dkpDecayPercent); }
      if (body.dkpDecayInactiveDays !== undefined) { sets.push('dkp_decay_inactive_days = ?'); vals.push(body.dkpDecayInactiveDays); }
      if (body.dkpDecayIntervalDays !== undefined) { sets.push('dkp_decay_interval_days = ?'); vals.push(body.dkpDecayIntervalDays); }
      if (body.accentColor !== undefined) { sets.push('accent_color = ?'); vals.push(body.accentColor || null); }
      if (body.teamIcon !== undefined) { sets.push('team_icon = ?'); vals.push(body.teamIcon || null); }
      if (sets.length > 0) {
        vals.push(teamId);
        await env.DB.prepare(`UPDATE team_settings SET ${sets.join(', ')} WHERE team_id = ?`).bind(...vals).run();
      }
    } else {
      await env.DB.prepare('INSERT INTO team_settings (team_id, webhook_url, on_warning, on_spawn, on_announcement, timezone) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(teamId, body.webhookUrl || null, body.onWarning !== false ? 1 : 0, body.onSpawn !== false ? 1 : 0, body.onAnnouncement !== false ? 1 : 0, body.timezone || 'Asia/Manila').run();
    }

    return json({ ok: true });
  }

  // POST /api/teams/:id/transfer — transfer ownership (leader only)
  const transferMatch = path.match(/^\/api\/teams\/([^/]+)\/transfer$/);
  if (transferMatch && request.method === 'POST') {
    const teamId = transferMatch[1];
    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ? AND owner_id = ?')
      .bind(teamId, user.userId).first();
    if (!team) return json({ error: 'Not the owner' }, 403);

    const body = await request.json();
    if (!body.userId) return json({ error: 'User required' }, 400);

    const target = await env.DB.prepare('SELECT * FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, body.userId).first();
    if (!target) return json({ error: 'User not in team' }, 400);

    await env.DB.batch([
      env.DB.prepare('UPDATE teams SET owner_id = ? WHERE id = ?').bind(body.userId, teamId),
      env.DB.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?').bind('leader', teamId, body.userId),
      env.DB.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?').bind('officer', teamId, user.userId),
    ]);
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

    // Check if members can create events
    if (member.role === 'member') {
      const ts = await env.DB.prepare('SELECT members_create_events FROM team_settings WHERE team_id = ?').bind(teamId).first();
      if (ts && !ts.members_create_events) return json({ error: 'Only officers+ can create events' }, 403);
    }

    const body = await request.json();
    if (!body.title?.trim() || !body.eventTime) return json({ error: 'Title and time required' }, 400);

    const id = crypto.randomUUID();
    const recurrence = ['daily', 'weekly', 'biweekly', 'monthly'].includes(body.recurrence) ? body.recurrence : null;
    await env.DB.prepare(`INSERT INTO events (id, team_id, title, description, event_type, event_time, duration_minutes, created_by, recurrence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, teamId, body.title.trim(), body.description || null, body.eventType || 'other',
        body.eventTime, body.durationMinutes || 60, user.userId, recurrence).run();

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

  // --- Announcements ---

  // GET/POST /api/teams/:id/announcements
  const announcementListMatch = path.match(/^\/api\/teams\/([^/]+)\/announcements$/);
  if (announcementListMatch && request.method === 'GET') {
    const teamId = announcementListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const announcements = await env.DB.prepare(`
      SELECT a.*, u.username as author_name
      FROM announcements a JOIN users u ON u.id = a.created_by
      WHERE a.team_id = ?
      ORDER BY a.pinned DESC, a.created_at DESC
    `).bind(teamId).all();

    return json({ announcements: announcements.results });
  }

  if (announcementListMatch && request.method === 'POST') {
    const teamId = announcementListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    if (!body.title?.trim()) return json({ error: 'Title required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO announcements (id, team_id, title, body, pinned, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.title.trim(), body.body || null, body.pinned ? 1 : 0, user.userId).run();

    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    if (settings?.webhook_url && settings?.on_announcement !== 0) {
      await sendDiscord(settings.webhook_url, `Announcement: ${body.title.trim()}`,
        `**${body.title.trim()}**${body.body ? '\n\n' + body.body.substring(0, 1500) : ''}\n\n— ${user.username}`, 5793266);
    }

    return json({ ok: true, id });
  }

  // PUT/DELETE /api/teams/:id/announcements/:announcementId
  const announcementMatch = path.match(/^\/api\/teams\/([^/]+)\/announcements\/([^/]+)$/);
  if (announcementMatch && request.method === 'PUT') {
    const [, teamId, announcementId] = announcementMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    await env.DB.prepare('UPDATE announcements SET title = ?, body = ?, pinned = ? WHERE id = ? AND team_id = ?')
      .bind(body.title?.trim(), body.body || null, body.pinned ? 1 : 0, announcementId, teamId).run();
    return json({ ok: true });
  }

  if (announcementMatch && request.method === 'DELETE') {
    const [, teamId, announcementId] = announcementMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const announcement = await env.DB.prepare('SELECT * FROM announcements WHERE id = ? AND team_id = ?').bind(announcementId, teamId).first();
    if (!announcement) return json({ error: 'Not found' }, 404);
    if (announcement.created_by !== user.userId && member.role === 'member') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM announcements WHERE id = ?').bind(announcementId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/announcements/:id/pin — toggle pin
  const pinMatch = path.match(/^\/api\/teams\/([^/]+)\/announcements\/([^/]+)\/pin$/);
  if (pinMatch && request.method === 'POST') {
    const [, teamId, announcementId] = pinMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const a = await env.DB.prepare('SELECT pinned FROM announcements WHERE id = ? AND team_id = ?').bind(announcementId, teamId).first();
    if (!a) return json({ error: 'Not found' }, 404);

    await env.DB.prepare('UPDATE announcements SET pinned = ? WHERE id = ?').bind(a.pinned ? 0 : 1, announcementId).run();
    return json({ ok: true, pinned: !a.pinned });
  }

  // --- Member Notes ---

  // GET/POST /api/teams/:id/members/:userId/notes
  const notesMatch = path.match(/^\/api\/teams\/([^/]+)\/members\/([^/]+)\/notes$/);
  if (notesMatch && request.method === 'GET') {
    const [, teamId, targetUserId] = notesMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const notes = await env.DB.prepare(`
      SELECT n.*, u.username as author_name
      FROM member_notes n JOIN users u ON u.id = n.author_id
      WHERE n.team_id = ? AND n.target_user_id = ?
      ORDER BY n.created_at DESC
    `).bind(teamId, targetUserId).all();

    return json({ notes: notes.results });
  }

  if (notesMatch && request.method === 'POST') {
    const [, teamId, targetUserId] = notesMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    if (!body.note?.trim()) return json({ error: 'Note required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO member_notes (id, team_id, target_user_id, author_id, note) VALUES (?, ?, ?, ?, ?)')
      .bind(id, teamId, targetUserId, user.userId, body.note.trim()).run();
    return json({ ok: true, id });
  }

  // DELETE /api/teams/:id/notes/:noteId
  const noteDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/notes\/([^/]+)$/);
  if (noteDeleteMatch && request.method === 'DELETE') {
    const [, teamId, noteId] = noteDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const note = await env.DB.prepare('SELECT * FROM member_notes WHERE id = ? AND team_id = ?').bind(noteId, teamId).first();
    if (!note) return json({ error: 'Not found' }, 404);
    if (note.author_id !== user.userId && member.role !== 'leader') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM member_notes WHERE id = ?').bind(noteId).run();
    return json({ ok: true });
  }

  // --- Activity Heartbeat ---

  const heartbeatMatch = path.match(/^\/api\/teams\/([^/]+)\/heartbeat$/);
  if (heartbeatMatch && request.method === 'POST') {
    const teamId = heartbeatMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    await env.DB.prepare('INSERT OR REPLACE INTO member_activity (team_id, user_id, last_seen) VALUES (?, ?, unixepoch())')
      .bind(teamId, user.userId).run();
    return json({ ok: true });
  }

  // --- Chat ---

  const chatMatch = path.match(/^\/api\/teams\/([^/]+)\/chat$/);
  if (chatMatch && request.method === 'GET') {
    const teamId = chatMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const url = new URL(request.url);
    const after = url.searchParams.get('after') || '0';

    const messages = await env.DB.prepare(`
      SELECT cm.*, u.username, u.avatar, u.discord_id
      FROM chat_messages cm JOIN users u ON u.id = cm.user_id
      WHERE cm.team_id = ? AND cm.created_at > ?
      ORDER BY cm.created_at ASC
      LIMIT 100
    `).bind(teamId, parseInt(after)).all();

    // Attach reactions
    const msgIds = messages.results.map(m => m.id);
    if (msgIds.length > 0) {
      const reactions = await env.DB.prepare(
        `SELECT * FROM chat_reactions WHERE message_id IN (${msgIds.map(() => '?').join(',')})`)
        .bind(...msgIds).all().catch(() => ({ results: [] }));
      const reactionMap = {};
      for (const r of reactions.results) {
        if (!reactionMap[r.message_id]) reactionMap[r.message_id] = [];
        reactionMap[r.message_id].push(r);
      }
      for (const m of messages.results) m.reactions = reactionMap[m.id] || [];
    }

    return json({ messages: messages.results });
  }

  if (chatMatch && request.method === 'POST') {
    const teamId = chatMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json();
    if (!body.message?.trim()) return json({ error: 'Message required' }, 400);
    if (body.message.length > 2000) return json({ error: 'Message too long' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO chat_messages (id, team_id, user_id, message) VALUES (?, ?, ?, ?)')
      .bind(id, teamId, user.userId, body.message.trim()).run();

    return json({ ok: true, id });
  }

  // DELETE single message (author or officers+)
  const chatDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/chat\/([^/]+)$/);
  if (chatDeleteMatch && request.method === 'DELETE') {
    const [, teamId, msgId] = chatDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const msg = await env.DB.prepare('SELECT * FROM chat_messages WHERE id = ? AND team_id = ?').bind(msgId, teamId).first();
    if (!msg) return json({ error: 'Not found' }, 404);
    if (msg.user_id !== user.userId && member.role === 'member') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM chat_messages WHERE id = ?').bind(msgId).run();
    return json({ ok: true });
  }

  // --- Boss Loot ---

  const lootListMatch = path.match(/^\/api\/teams\/([^/]+)\/loot$/);
  if (lootListMatch && request.method === 'GET') {
    const teamId = lootListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const loot = await env.DB.prepare(`
      SELECT bl.*, u.username as recipient_name, u2.username as noted_by_name
      FROM boss_loot bl
      JOIN users u ON u.id = bl.recipient_id
      JOIN users u2 ON u2.id = bl.noted_by
      WHERE bl.team_id = ?
      ORDER BY bl.created_at DESC
      LIMIT 100
    `).bind(teamId).all();

    return json({ loot: loot.results });
  }

  if (lootListMatch && request.method === 'POST') {
    const teamId = lootListMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    if (!body.itemName?.trim() || !body.recipientId) return json({ error: 'Item and recipient required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO boss_loot (id, team_id, boss_id, boss_name, item_name, recipient_id, dkp_cost, noted_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.bossId || null, body.bossName || 'Unknown', body.itemName.trim(), body.recipientId, body.dkpCost || 0, user.userId).run();

    // Deduct DKP if cost > 0
    if (body.dkpCost && body.dkpCost > 0) {
      const dkpId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(dkpId, teamId, body.recipientId, -body.dkpCost, `Loot: ${body.itemName.trim()}`, user.userId).run();
    }

    return json({ ok: true, id });
  }

  const lootDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/loot\/([^/]+)$/);
  if (lootDeleteMatch && request.method === 'DELETE') {
    const [, teamId, lootId] = lootDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    await env.DB.prepare('DELETE FROM boss_loot WHERE id = ? AND team_id = ?').bind(lootId, teamId).run();
    return json({ ok: true });
  }

  // --- DKP ---

  const dkpMatch = path.match(/^\/api\/teams\/([^/]+)\/dkp$/);
  if (dkpMatch && request.method === 'GET') {
    const teamId = dkpMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    // Get balances (sum of ledger per user)
    const balances = await env.DB.prepare(`
      SELECT dl.user_id, u.username, u.avatar, u.discord_id, SUM(dl.amount) as balance
      FROM dkp_ledger dl JOIN users u ON u.id = dl.user_id
      WHERE dl.team_id = ?
      GROUP BY dl.user_id
      ORDER BY balance DESC
    `).bind(teamId).all();

    return json({ balances: balances.results });
  }

  if (dkpMatch && request.method === 'POST') {
    const teamId = dkpMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    if (!body.userId || !body.amount || !body.reason?.trim()) return json({ error: 'User, amount, and reason required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.userId, body.amount, body.reason.trim(), user.userId).run();

    return json({ ok: true, id });
  }

  // GET /api/teams/:id/dkp/history — full ledger
  const dkpHistoryMatch = path.match(/^\/api\/teams\/([^/]+)\/dkp\/history$/);
  if (dkpHistoryMatch && request.method === 'GET') {
    const teamId = dkpHistoryMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const history = await env.DB.prepare(`
      SELECT dl.*, u.username, u2.username as created_by_name
      FROM dkp_ledger dl
      JOIN users u ON u.id = dl.user_id
      JOIN users u2 ON u2.id = dl.created_by
      WHERE dl.team_id = ?
      ORDER BY dl.created_at DESC
      LIMIT 100
    `).bind(teamId).all();

    return json({ history: history.results });
  }

  // POST /api/teams/:id/dkp/bulk — award DKP to multiple members
  const dkpBulkMatch = path.match(/^\/api\/teams\/([^/]+)\/dkp\/bulk$/);
  if (dkpBulkMatch && request.method === 'POST') {
    const teamId = dkpBulkMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    // body.userIds = [...], body.amount, body.reason
    if (!body.userIds?.length || !body.amount || !body.reason?.trim()) return json({ error: 'Users, amount, and reason required' }, 400);

    for (const userId of body.userIds) {
      const id = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(id, teamId, userId, body.amount, body.reason.trim(), user.userId).run();
    }

    return json({ ok: true });
  }

  // --- War Log & Stats ---

  const warLogMatch = path.match(/^\/api\/teams\/([^/]+)\/wars$/);
  if (warLogMatch && request.method === 'GET') {
    const teamId = warLogMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const wars = await env.DB.prepare(`
      SELECT wl.*, u.username as logged_by_name
      FROM war_log wl JOIN users u ON u.id = wl.logged_by
      WHERE wl.team_id = ?
      ORDER BY wl.war_date DESC
      LIMIT 100
    `).bind(teamId).all();

    // Compute stats
    const results = wars.results;
    const stats = { wins: 0, losses: 0, draws: 0, byOpponent: {} };
    for (const w of results) {
      if (w.result === 'win') stats.wins++;
      else if (w.result === 'loss') stats.losses++;
      else stats.draws++;

      if (!stats.byOpponent[w.opponent]) stats.byOpponent[w.opponent] = { wins: 0, losses: 0, draws: 0 };
      if (w.result === 'win') stats.byOpponent[w.opponent].wins++;
      else if (w.result === 'loss') stats.byOpponent[w.opponent].losses++;
      else stats.byOpponent[w.opponent].draws++;
    }

    return json({ wars: results, stats });
  }

  if (warLogMatch && request.method === 'POST') {
    const teamId = warLogMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await request.json();
    if (!body.opponent?.trim() || !['win', 'loss', 'draw'].includes(body.result)) {
      return json({ error: 'Opponent and result (win/loss/draw) required' }, 400);
    }

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO war_log (id, team_id, opponent, result, event_type, score_us, score_them, notes, war_date, logged_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.opponent.trim(), body.result, body.eventType || 'gvg',
        body.scoreUs ?? null, body.scoreThem ?? null, body.notes || null,
        body.warDate || Math.floor(Date.now() / 1000), user.userId).run();

    // Discord notification
    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    if (settings?.webhook_url && settings?.on_war !== 0) {
      const emoji = body.result === 'win' ? '🏆' : body.result === 'loss' ? '❌' : '🤝';
      const scoreText = body.scoreUs !== undefined && body.scoreThem !== undefined ? ` (${body.scoreUs}-${body.scoreThem})` : '';
      await sendDiscord(settings.webhook_url, `War Result: ${body.result.toUpperCase()}`,
        `${emoji} **${body.result.toUpperCase()}** vs **${body.opponent.trim()}**${scoreText}${body.notes ? '\n' + body.notes : ''}`,
        body.result === 'win' ? 5763719 : body.result === 'loss' ? 15548997 : 16760576);
    }

    return json({ ok: true, id });
  }

  const warDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/wars\/([^/]+)$/);
  if (warDeleteMatch && request.method === 'DELETE') {
    const [, teamId, warId] = warDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    await env.DB.prepare('DELETE FROM war_log WHERE id = ? AND team_id = ?').bind(warId, teamId).run();
    return json({ ok: true });
  }

  // --- Premium: Chat Reactions ---

  const reactMatch = path.match(/^\/api\/teams\/([^/]+)\/chat\/([^/]+)\/react$/);
  if (reactMatch && request.method === 'POST') {
    const [, teamId, msgId] = reactMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    if (!body.emoji) return json({ error: 'Emoji required' }, 400);

    const existing = await env.DB.prepare('SELECT 1 FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
      .bind(msgId, user.userId, body.emoji).first();
    if (existing) {
      await env.DB.prepare('DELETE FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
        .bind(msgId, user.userId, body.emoji).run();
    } else {
      await env.DB.prepare('INSERT INTO chat_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)')
        .bind(msgId, user.userId, body.emoji).run();
    }
    return json({ ok: true });
  }

  // --- Premium: Boss Templates ---

  if (path === '/api/boss-templates' && request.method === 'GET') {
    const templates = await env.DB.prepare('SELECT * FROM boss_templates WHERE is_global = 1 OR created_by = ? ORDER BY game, name')
      .bind(user.userId).all();
    return json({ templates: templates.results });
  }

  if (path === '/api/boss-templates' && request.method === 'POST') {
    const body = await request.json();
    if (!body.name?.trim() || !body.game?.trim() || !body.bosses) return json({ error: 'Name, game, and bosses required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO boss_templates (id, name, game, bosses, created_by) VALUES (?, ?, ?, ?, ?)')
      .bind(id, body.name.trim(), body.game.trim(), JSON.stringify(body.bosses), user.userId).run();
    return json({ ok: true, id });
  }

  const bossTemplateDeleteMatch = path.match(/^\/api\/boss-templates\/([^/]+)$/);
  if (bossTemplateDeleteMatch && request.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM boss_templates WHERE id = ? AND created_by = ?')
      .bind(bossTemplateDeleteMatch[1], user.userId).run();
    return json({ ok: true });
  }

  const importTemplateMatch = path.match(/^\/api\/teams\/([^/]+)\/bosses\/import-template$/);
  if (importTemplateMatch && request.method === 'POST') {
    const teamId = importTemplateMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    const template = await env.DB.prepare('SELECT * FROM boss_templates WHERE id = ?').bind(body.templateId).first();
    if (!template) return json({ error: 'Template not found' }, 404);

    const bosses = JSON.parse(template.bosses);
    const settings = await env.DB.prepare('SELECT timezone FROM team_settings WHERE team_id = ?').bind(teamId).first();
    const tz = settings?.timezone || 'Asia/Manila';

    for (const b of bosses) {
      const id = crypto.randomUUID();
      const nextSpawn = Date.now() + (b.intervalMs || 3600000);
      await env.DB.prepare('INSERT INTO bosses (id, team_id, name, type, interval_ms, fixed_time, weekly_day, weekly_time, biweekly_days, alert_minutes, next_spawn) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
        .bind(id, teamId, b.name, b.type || 'interval', b.intervalMs || null, b.fixedTime || null, b.weeklyDay ?? null, b.weeklyTime || null, b.biweeklyDays ? JSON.stringify(b.biweeklyDays) : null, b.alertMinutes || 5, nextSpawn).run();
    }
    return json({ ok: true, count: bosses.length });
  }

  // --- Premium: Boss History ---

  const bossHistoryMatch = path.match(/^\/api\/teams\/([^/]+)\/bosses\/history$/);
  if (bossHistoryMatch && request.method === 'GET') {
    const teamId = bossHistoryMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const history = await env.DB.prepare(`
      SELECT bkl.*, u.username as killed_by_name
      FROM boss_kill_log bkl LEFT JOIN users u ON u.id = bkl.killed_by
      WHERE bkl.team_id = ? ORDER BY bkl.killed_at DESC LIMIT 100
    `).bind(teamId).all();

    // Stats per boss
    const stats = await env.DB.prepare(`
      SELECT boss_name, COUNT(*) as kill_count, MAX(killed_at) as last_kill
      FROM boss_kill_log WHERE team_id = ? GROUP BY boss_name ORDER BY kill_count DESC
    `).bind(teamId).all();

    return json({ history: history.results, stats: stats.results });
  }

  // --- Premium: Event Templates ---

  const eventTemplateMatch = path.match(/^\/api\/teams\/([^/]+)\/event-templates$/);
  if (eventTemplateMatch && request.method === 'GET') {
    const teamId = eventTemplateMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const templates = await env.DB.prepare('SELECT * FROM event_templates WHERE team_id = ? ORDER BY name')
      .bind(teamId).all();
    return json({ templates: templates.results });
  }

  if (eventTemplateMatch && request.method === 'POST') {
    const teamId = eventTemplateMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    if (!body.name?.trim() || !body.title?.trim()) return json({ error: 'Name and title required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO event_templates (id, team_id, name, title, description, event_type, duration_minutes, recurrence, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.name.trim(), body.title.trim(), body.description || null, body.eventType || 'other', body.durationMinutes || 60, body.recurrence || null, user.userId).run();
    return json({ ok: true, id });
  }

  const eventTemplateDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/event-templates\/([^/]+)$/);
  if (eventTemplateDeleteMatch && request.method === 'DELETE') {
    const [, teamId, templateId] = eventTemplateDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    await env.DB.prepare('DELETE FROM event_templates WHERE id = ? AND team_id = ?').bind(templateId, teamId).run();
    return json({ ok: true });
  }

  // --- Premium: Attendance Report ---

  const attendReportMatch = path.match(/^\/api\/teams\/([^/]+)\/attendance-report$/);
  if (attendReportMatch && request.method === 'GET') {
    const teamId = attendReportMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const report = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar,
        (SELECT COUNT(DISTINCT ea.event_id) FROM event_attendance ea
         JOIN events e ON e.id = ea.event_id WHERE ea.user_id = u.id AND e.team_id = ? AND ea.attended = 1) as attended,
        (SELECT COUNT(*) FROM events WHERE team_id = ?) as total_events,
        (SELECT COUNT(DISTINCT er.event_id) FROM event_rsvps er
         JOIN events e ON e.id = er.event_id WHERE er.user_id = u.id AND e.team_id = ? AND er.status = 'going') as rsvp_going
      FROM team_members tm JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = ?
      ORDER BY attended DESC
    `).bind(teamId, teamId, teamId, teamId).all();

    return json({ report: report.results });
  }

  // --- Premium: Loot Wishlist ---

  const wishlistMatch = path.match(/^\/api\/teams\/([^/]+)\/wishlist$/);
  if (wishlistMatch && request.method === 'GET') {
    const teamId = wishlistMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const query = member.role === 'member'
      ? 'SELECT lw.*, u.username FROM loot_wishlist lw JOIN users u ON u.id = lw.user_id WHERE lw.team_id = ? AND lw.user_id = ? ORDER BY lw.priority DESC'
      : 'SELECT lw.*, u.username FROM loot_wishlist lw JOIN users u ON u.id = lw.user_id WHERE lw.team_id = ? ORDER BY lw.item_name, lw.priority DESC';

    const wishes = member.role === 'member'
      ? await env.DB.prepare(query).bind(teamId, user.userId).all()
      : await env.DB.prepare(query).bind(teamId).all();

    return json({ wishes: wishes.results });
  }

  if (wishlistMatch && request.method === 'POST') {
    const teamId = wishlistMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    if (!body.itemName?.trim()) return json({ error: 'Item name required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO loot_wishlist (id, team_id, user_id, item_name, boss_name, priority) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, user.userId, body.itemName.trim(), body.bossName || null, body.priority || 1).run();
    return json({ ok: true, id });
  }

  const wishlistDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/wishlist\/([^/]+)$/);
  if (wishlistDeleteMatch && request.method === 'DELETE') {
    const [, teamId, wishId] = wishlistDeleteMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    await env.DB.prepare('DELETE FROM loot_wishlist WHERE id = ? AND (user_id = ? OR ? IN ("leader","officer"))')
      .bind(wishId, user.userId, member.role).run();
    return json({ ok: true });
  }

  // --- Premium: DKP Auctions ---

  const auctionMatch = path.match(/^\/api\/teams\/([^/]+)\/auctions$/);
  if (auctionMatch && request.method === 'GET') {
    const teamId = auctionMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const auctions = await env.DB.prepare(`
      SELECT da.*, u.username as started_by_name, w.username as winner_name,
        (SELECT MAX(amount) FROM dkp_bids WHERE auction_id = da.id) as top_bid,
        (SELECT COUNT(*) FROM dkp_bids WHERE auction_id = da.id) as bid_count
      FROM dkp_auctions da
      JOIN users u ON u.id = da.started_by
      LEFT JOIN users w ON w.id = da.winner_id
      WHERE da.team_id = ? ORDER BY da.status ASC, da.created_at DESC LIMIT 50
    `).bind(teamId).all();
    return json({ auctions: auctions.results });
  }

  if (auctionMatch && request.method === 'POST') {
    const teamId = auctionMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    if (!body.itemName?.trim()) return json({ error: 'Item name required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO dkp_auctions (id, team_id, item_name, boss_name, started_by, min_bid, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.itemName.trim(), body.bossName || null, user.userId, body.minBid || 0, body.expiresAt || null).run();
    return json({ ok: true, id });
  }

  const auctionBidMatch = path.match(/^\/api\/teams\/([^/]+)\/auctions\/([^/]+)\/bid$/);
  if (auctionBidMatch && request.method === 'POST') {
    const [, teamId, auctionId] = auctionBidMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const auction = await env.DB.prepare('SELECT * FROM dkp_auctions WHERE id = ? AND team_id = ? AND status = ?')
      .bind(auctionId, teamId, 'open').first();
    if (!auction) return json({ error: 'Auction not found or closed' }, 404);

    const body = await request.json();
    if (!body.amount || body.amount <= 0) return json({ error: 'Invalid bid' }, 400);
    if (body.amount < (auction.min_bid || 0)) return json({ error: `Minimum bid is ${auction.min_bid}` }, 400);

    // Check DKP balance
    const bal = await env.DB.prepare('SELECT COALESCE(SUM(amount),0) as balance FROM dkp_ledger WHERE team_id = ? AND user_id = ?')
      .bind(teamId, user.userId).first();
    if (bal.balance < body.amount) return json({ error: 'Not enough DKP' }, 400);

    // Check higher bid exists
    const topBid = await env.DB.prepare('SELECT MAX(amount) as top FROM dkp_bids WHERE auction_id = ?').bind(auctionId).first();
    if (topBid.top && body.amount <= topBid.top) return json({ error: `Must bid higher than ${topBid.top}` }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO dkp_bids (id, auction_id, user_id, amount) VALUES (?, ?, ?, ?)')
      .bind(id, auctionId, user.userId, body.amount).run();
    return json({ ok: true });
  }

  const auctionCloseMatch = path.match(/^\/api\/teams\/([^/]+)\/auctions\/([^/]+)\/close$/);
  if (auctionCloseMatch && request.method === 'POST') {
    const [, teamId, auctionId] = auctionCloseMatch;
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const auction = await env.DB.prepare('SELECT * FROM dkp_auctions WHERE id = ? AND team_id = ? AND status = ?')
      .bind(auctionId, teamId, 'open').first();
    if (!auction) return json({ error: 'Auction not found or already closed' }, 404);

    const topBid = await env.DB.prepare('SELECT * FROM dkp_bids WHERE auction_id = ? ORDER BY amount DESC LIMIT 1')
      .bind(auctionId).first();

    if (topBid) {
      // Deduct DKP from winner
      const dkpId = crypto.randomUUID();
      await env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(dkpId, teamId, topBid.user_id, -topBid.amount, `Auction: ${auction.item_name}`, user.userId).run();
      await env.DB.prepare('UPDATE dkp_auctions SET status = ?, winner_id = ?, winning_bid = ? WHERE id = ?')
        .bind('closed', topBid.user_id, topBid.amount, auctionId).run();
    } else {
      await env.DB.prepare('UPDATE dkp_auctions SET status = ? WHERE id = ?').bind('closed', auctionId).run();
    }
    return json({ ok: true, winner: topBid?.user_id || null });
  }

  // --- Premium: Analytics ---

  const analyticsMatch = path.match(/^\/api\/teams\/([^/]+)\/analytics$/);
  if (analyticsMatch && request.method === 'GET') {
    const teamId = analyticsMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const url = new URL(request.url);
    const type = url.searchParams.get('type') || 'activity';

    if (type === 'activity') {
      const activity = await env.DB.prepare(`
        SELECT u.username, ma.last_seen FROM member_activity ma
        JOIN users u ON u.id = ma.user_id WHERE ma.team_id = ?
      `).bind(teamId).all();
      return json({ data: activity.results });
    } else if (type === 'wars') {
      const wars = await env.DB.prepare(`
        SELECT result, war_date, opponent FROM war_log WHERE team_id = ? ORDER BY war_date ASC
      `).bind(teamId).all();
      return json({ data: wars.results });
    } else if (type === 'dkp') {
      const dkp = await env.DB.prepare(`
        SELECT dl.user_id, u.username, dl.amount, dl.reason, dl.created_at
        FROM dkp_ledger dl JOIN users u ON u.id = dl.user_id
        WHERE dl.team_id = ? ORDER BY dl.created_at ASC
      `).bind(teamId).all();
      return json({ data: dkp.results });
    } else if (type === 'attendance') {
      const att = await env.DB.prepare(`
        SELECT u.username, COUNT(CASE WHEN ea.attended = 1 THEN 1 END) as attended,
          COUNT(e.id) as total
        FROM team_members tm
        JOIN users u ON u.id = tm.user_id
        LEFT JOIN events e ON e.team_id = tm.team_id
        LEFT JOIN event_attendance ea ON ea.event_id = e.id AND ea.user_id = tm.user_id
        WHERE tm.team_id = ? GROUP BY u.id ORDER BY attended DESC
      `).bind(teamId).all();
      return json({ data: att.results });
    }
    return json({ data: [] });
  }

  // --- Premium: CSV Export ---

  const exportMatch = path.match(/^\/api\/teams\/([^/]+)\/export$/);
  if (exportMatch && request.method === 'GET') {
    const teamId = exportMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const url = new URL(request.url);
    const type = url.searchParams.get('type') || 'members';
    let csv = '';

    if (type === 'members') {
      csv = 'Username,Role,Joined\n';
      const rows = await env.DB.prepare('SELECT u.username, tm.role, tm.joined_at FROM team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = ?').bind(teamId).all();
      for (const r of rows.results) csv += `${r.username},${r.role},${new Date(r.joined_at * 1000).toISOString()}\n`;
    } else if (type === 'dkp') {
      csv = 'Username,Amount,Reason,Date\n';
      const rows = await env.DB.prepare('SELECT u.username, dl.amount, dl.reason, dl.created_at FROM dkp_ledger dl JOIN users u ON u.id = dl.user_id WHERE dl.team_id = ? ORDER BY dl.created_at DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.username}",${r.amount},"${r.reason}",${new Date(r.created_at * 1000).toISOString()}\n`;
    } else if (type === 'wars') {
      csv = 'Opponent,Result,Score,Date\n';
      const rows = await env.DB.prepare('SELECT * FROM war_log WHERE team_id = ? ORDER BY war_date DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.opponent}",${r.result},${r.score_us ?? ''}-${r.score_them ?? ''},${new Date(r.war_date * 1000).toISOString()}\n`;
    } else if (type === 'loot') {
      csv = 'Item,Boss,Recipient,DKP Cost,Date\n';
      const rows = await env.DB.prepare('SELECT bl.*, u.username FROM boss_loot bl JOIN users u ON u.id = bl.recipient_id WHERE bl.team_id = ? ORDER BY bl.created_at DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.item_name}","${r.boss_name}","${r.username}",${r.dkp_cost},${new Date(r.created_at * 1000).toISOString()}\n`;
    }

    return new Response(csv, {
      headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${type}-export.csv"`, ...corsHeaders() },
    });
  }

  // --- Premium: Custom Roles ---

  const rolesMatch = path.match(/^\/api\/teams\/([^/]+)\/roles$/);
  if (rolesMatch && request.method === 'GET') {
    const teamId = rolesMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const roles = await env.DB.prepare('SELECT * FROM custom_roles WHERE team_id = ?').bind(teamId).all();
    const roleMap = {};
    for (const r of roles.results) roleMap[r.base_role] = { displayName: r.display_name, color: r.color };
    return json({ roles: roleMap });
  }

  if (rolesMatch && request.method === 'PUT') {
    const teamId = rolesMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || member.role !== 'leader') return json({ error: 'Leader only' }, 403);
    if (!(await isPremiumTeam(teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await request.json();
    // body.roles = { leader: {displayName, color}, officer: {...}, member: {...} }
    await env.DB.prepare('DELETE FROM custom_roles WHERE team_id = ?').bind(teamId).run();
    for (const [role, data] of Object.entries(body.roles || {})) {
      if (['leader', 'officer', 'member'].includes(role) && data.displayName?.trim()) {
        await env.DB.prepare('INSERT INTO custom_roles (team_id, base_role, display_name, color) VALUES (?, ?, ?, ?)')
          .bind(teamId, role, data.displayName.trim(), data.color || null).run();
      }
    }
    return json({ ok: true });
  }

  // --- Availability ---

  // GET /api/teams/:id/availability — get all members' availability
  const availMatch = path.match(/^\/api\/teams\/([^/]+)\/availability$/);
  if (availMatch && request.method === 'GET') {
    const teamId = availMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const slots = await env.DB.prepare(`
      SELECT ma.*, u.username
      FROM member_availability ma JOIN users u ON u.id = ma.user_id
      WHERE ma.team_id = ?
      ORDER BY ma.day, ma.start_time
    `).bind(teamId).all();

    return json({ slots: slots.results });
  }

  // PUT /api/teams/:id/availability — set my availability (replaces all my slots)
  if (availMatch && request.method === 'PUT') {
    const teamId = availMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json();
    // body.slots = [{day: 0-6, startTime: "HH:MM", endTime: "HH:MM"}, ...]
    await env.DB.prepare('DELETE FROM member_availability WHERE team_id = ? AND user_id = ?')
      .bind(teamId, user.userId).run();

    for (const slot of (body.slots || [])) {
      if (slot.day === undefined || !slot.startTime || !slot.endTime) continue;
      await env.DB.prepare('INSERT INTO member_availability (team_id, user_id, day, start_time, end_time) VALUES (?, ?, ?, ?, ?)')
        .bind(teamId, user.userId, slot.day, slot.startTime, slot.endTime).run();
    }

    return json({ ok: true });
  }

  // ========== POLLS ==========

  const pollsMatch = path.match(/^\/api\/teams\/([^/]+)\/polls$/);
  const pollMatch = path.match(/^\/api\/teams\/([^/]+)\/polls\/([^/]+)$/);
  const pollVoteMatch = path.match(/^\/api\/teams\/([^/]+)\/polls\/([^/]+)\/vote$/);
  const pollCloseMatch = path.match(/^\/api\/teams\/([^/]+)\/polls\/([^/]+)\/close$/);

  // GET /api/teams/:id/polls
  if (pollsMatch && request.method === 'GET') {
    const teamId = pollsMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const polls = await env.DB.prepare(`
      SELECT p.*, u.username as created_by_name FROM polls p
      LEFT JOIN users u ON u.id = p.created_by
      WHERE p.team_id = ? ORDER BY p.created_at DESC
    `).bind(teamId).all();

    // Get options and votes for each poll
    for (const poll of polls.results) {
      const options = await env.DB.prepare('SELECT * FROM poll_options WHERE poll_id = ? ORDER BY sort_order').bind(poll.id).all();
      poll.options = options.results;
      for (const opt of poll.options) {
        const votes = await env.DB.prepare('SELECT pv.user_id, u.username FROM poll_votes pv LEFT JOIN users u ON u.id = pv.user_id WHERE pv.option_id = ?').bind(opt.id).all();
        opt.votes = votes.results;
      }
      const myVotes = await env.DB.prepare('SELECT option_id FROM poll_votes WHERE poll_id = ? AND user_id = ?').bind(poll.id, user.userId).all();
      poll.myVotes = myVotes.results.map(v => v.option_id);
    }

    return json({ polls: polls.results });
  }

  // POST /api/teams/:id/polls — create poll
  if (pollsMatch && request.method === 'POST') {
    const teamId = pollsMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json();
    if (!body.question || !body.options || body.options.length < 2) return json({ error: 'Question and at least 2 options required' }, 400);

    const pollId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO polls (id, team_id, question, poll_type, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(pollId, teamId, body.question.slice(0, 200), body.pollType || 'single', user.userId, body.expiresAt || null).run();

    for (let i = 0; i < body.options.length && i < 10; i++) {
      await env.DB.prepare('INSERT INTO poll_options (id, poll_id, label, sort_order) VALUES (?, ?, ?, ?)')
        .bind(crypto.randomUUID(), pollId, body.options[i].slice(0, 100), i).run();
    }

    return json({ ok: true, id: pollId });
  }

  // POST /api/teams/:id/polls/:pollId/vote
  if (pollVoteMatch && request.method === 'POST') {
    const teamId = pollVoteMatch[1];
    const pollId = pollVoteMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const poll = await env.DB.prepare('SELECT * FROM polls WHERE id = ? AND team_id = ?').bind(pollId, teamId).first();
    if (!poll) return json({ error: 'Poll not found' }, 404);
    if (poll.closed) return json({ error: 'Poll is closed' }, 400);
    if (poll.expires_at && poll.expires_at < Math.floor(Date.now() / 1000)) return json({ error: 'Poll has expired' }, 400);

    const body = await request.json();
    const optionIds = Array.isArray(body.optionIds) ? body.optionIds : [body.optionId];

    // Clear previous votes
    await env.DB.prepare('DELETE FROM poll_votes WHERE poll_id = ? AND user_id = ?').bind(pollId, user.userId).run();

    // Add new votes
    for (const optId of (poll.poll_type === 'single' ? optionIds.slice(0, 1) : optionIds)) {
      const opt = await env.DB.prepare('SELECT id FROM poll_options WHERE id = ? AND poll_id = ?').bind(optId, pollId).first();
      if (opt) {
        await env.DB.prepare('INSERT INTO poll_votes (poll_id, option_id, user_id) VALUES (?, ?, ?)')
          .bind(pollId, optId, user.userId).run();
      }
    }

    return json({ ok: true });
  }

  // POST /api/teams/:id/polls/:pollId/close
  if (pollCloseMatch && request.method === 'POST') {
    const teamId = pollCloseMatch[1];
    const pollId = pollCloseMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('UPDATE polls SET closed = 1 WHERE id = ? AND team_id = ?').bind(pollId, teamId).run();
    return json({ ok: true });
  }

  // DELETE /api/teams/:id/polls/:pollId
  if (pollMatch && request.method === 'DELETE') {
    const teamId = pollMatch[1];
    const pollId = pollMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM poll_votes WHERE poll_id = ?').bind(pollId).run();
    await env.DB.prepare('DELETE FROM poll_options WHERE poll_id = ?').bind(pollId).run();
    await env.DB.prepare('DELETE FROM polls WHERE id = ? AND team_id = ?').bind(pollId, teamId).run();
    return json({ ok: true });
  }

  // ========== ROSTERS ==========

  const rostersMatch = path.match(/^\/api\/teams\/([^/]+)\/rosters$/);
  const rosterMatch = path.match(/^\/api\/teams\/([^/]+)\/rosters\/([^/]+)$/);
  const rosterSlotMatch = path.match(/^\/api\/teams\/([^/]+)\/rosters\/([^/]+)\/slots$/);

  // GET /api/teams/:id/rosters
  if (rostersMatch && request.method === 'GET') {
    const teamId = rostersMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const rosters = await env.DB.prepare(`
      SELECT r.*, u.username as created_by_name FROM rosters r
      LEFT JOIN users u ON u.id = r.created_by
      WHERE r.team_id = ? ORDER BY r.created_at DESC
    `).bind(teamId).all();

    for (const roster of rosters.results) {
      const slots = await env.DB.prepare(`
        SELECT rs.*, u.username as assigned_name FROM roster_slots rs
        LEFT JOIN users u ON u.id = rs.user_id
        WHERE rs.roster_id = ? ORDER BY rs.sort_order
      `).bind(roster.id).all();
      roster.slots = slots.results;
    }

    return json({ rosters: rosters.results });
  }

  // POST /api/teams/:id/rosters — create roster
  if (rostersMatch && request.method === 'POST') {
    const teamId = rostersMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    if (!body.name) return json({ error: 'Name required' }, 400);

    const rosterId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO rosters (id, team_id, name, event_id, created_by) VALUES (?, ?, ?, ?, ?)')
      .bind(rosterId, teamId, body.name.slice(0, 100), body.eventId || null, user.userId).run();

    // Add initial slots
    for (let i = 0; i < (body.slots || []).length && i < 30; i++) {
      const s = body.slots[i];
      await env.DB.prepare('INSERT INTO roster_slots (id, roster_id, role_name, user_id, sort_order) VALUES (?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), rosterId, (s.roleName || 'Member').slice(0, 50), s.userId || null, i).run();
    }

    return json({ ok: true, id: rosterId });
  }

  // PUT /api/teams/:id/rosters/:rosterId/slots — update all slots
  if (rosterSlotMatch && request.method === 'PUT') {
    const teamId = rosterSlotMatch[1];
    const rosterId = rosterSlotMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    await env.DB.prepare('DELETE FROM roster_slots WHERE roster_id = ?').bind(rosterId).run();

    for (let i = 0; i < (body.slots || []).length && i < 30; i++) {
      const s = body.slots[i];
      await env.DB.prepare('INSERT INTO roster_slots (id, roster_id, role_name, user_id, sort_order) VALUES (?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), rosterId, (s.roleName || 'Member').slice(0, 50), s.userId || null, i).run();
    }

    return json({ ok: true });
  }

  // DELETE /api/teams/:id/rosters/:rosterId
  if (rosterMatch && request.method === 'DELETE') {
    const teamId = rosterMatch[1];
    const rosterId = rosterMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM roster_slots WHERE roster_id = ?').bind(rosterId).run();
    await env.DB.prepare('DELETE FROM rosters WHERE id = ? AND team_id = ?').bind(rosterId, teamId).run();
    return json({ ok: true });
  }

  // ========== PERFORMANCE TRACKER ==========

  const perfMatch = path.match(/^\/api\/teams\/([^/]+)\/performance$/);
  const perfDeleteMatch = path.match(/^\/api\/teams\/([^/]+)\/performance\/([^/]+)$/);

  // GET /api/teams/:id/performance
  if (perfMatch && request.method === 'GET') {
    const teamId = perfMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const entries = await env.DB.prepare(`
      SELECT pe.*, u.username as player_name, u2.username as logged_by_name FROM performance_entries pe
      LEFT JOIN users u ON u.id = pe.user_id
      LEFT JOIN users u2 ON u2.id = pe.logged_by
      WHERE pe.team_id = ? ORDER BY pe.created_at DESC LIMIT 200
    `).bind(teamId).all();

    // Build per-member averages
    const memberStats = {};
    for (const e of entries.results) {
      if (!memberStats[e.user_id]) memberStats[e.user_id] = { username: e.player_name, stats: {} };
      if (!memberStats[e.user_id].stats[e.stat_name]) memberStats[e.user_id].stats[e.stat_name] = { total: 0, count: 0 };
      memberStats[e.user_id].stats[e.stat_name].total += e.stat_value;
      memberStats[e.user_id].stats[e.stat_name].count++;
    }

    return json({ entries: entries.results, memberStats });
  }

  // POST /api/teams/:id/performance — log stats
  if (perfMatch && request.method === 'POST') {
    const teamId = perfMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    if (!body.userId || !body.eventLabel || !body.stats || !Array.isArray(body.stats)) return json({ error: 'userId, eventLabel, and stats[] required' }, 400);

    for (const stat of body.stats.slice(0, 20)) {
      if (!stat.name || stat.value === undefined) continue;
      await env.DB.prepare('INSERT INTO performance_entries (id, team_id, user_id, event_label, stat_name, stat_value, logged_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), teamId, body.userId, body.eventLabel.slice(0, 100), stat.name.slice(0, 50), Number(stat.value) || 0, user.userId).run();
    }

    return json({ ok: true });
  }

  // DELETE /api/teams/:id/performance/:entryId
  if (perfDeleteMatch && request.method === 'DELETE') {
    const teamId = perfDeleteMatch[1];
    const entryId = perfDeleteMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM performance_entries WHERE id = ? AND team_id = ?').bind(entryId, teamId).run();
    return json({ ok: true });
  }

  // ========== RECRUITMENT BOARD ==========

  const recruitMatch = path.match(/^\/api\/teams\/([^/]+)\/recruitment$/);
  const recruitPostMatch = path.match(/^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)$/);
  const recruitApplyMatch = path.match(/^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)\/apply$/);
  const recruitAppMatch = path.match(/^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)\/applications\/([^/]+)$/);

  // GET /api/teams/:id/recruitment
  if (recruitMatch && request.method === 'GET') {
    const teamId = recruitMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const posts = await env.DB.prepare(`
      SELECT rp.*, u.username as created_by_name FROM recruitment_posts rp
      LEFT JOIN users u ON u.id = rp.created_by
      WHERE rp.team_id = ? ORDER BY rp.created_at DESC
    `).bind(teamId).all();

    const canManage = member.role === 'leader' || member.role === 'officer';
    for (const post of posts.results) {
      if (canManage) {
        const apps = await env.DB.prepare(`
          SELECT ra.*, u.username as applicant_name, u.avatar as applicant_avatar FROM recruitment_applications ra
          LEFT JOIN users u ON u.id = ra.user_id
          WHERE ra.post_id = ? ORDER BY ra.created_at DESC
        `).bind(post.id).all();
        post.applications = apps.results;
      } else {
        const count = await env.DB.prepare('SELECT COUNT(*) as count FROM recruitment_applications WHERE post_id = ?').bind(post.id).first();
        post.applicationCount = count.count;
        // Check if current user applied
        const myApp = await env.DB.prepare('SELECT status FROM recruitment_applications WHERE post_id = ? AND user_id = ?').bind(post.id, user.userId).first();
        post.myApplication = myApp || null;
      }
    }

    return json({ posts: posts.results });
  }

  // POST /api/teams/:id/recruitment — create post
  if (recruitMatch && request.method === 'POST') {
    const teamId = recruitMatch[1];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    if (!body.title) return json({ error: 'Title required' }, 400);

    const postId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO recruitment_posts (id, team_id, title, description, role_needed, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(postId, teamId, body.title.slice(0, 100), (body.description || '').slice(0, 500), (body.roleNeeded || '').slice(0, 50), user.userId).run();

    return json({ ok: true, id: postId });
  }

  // PUT /api/teams/:id/recruitment/:postId — update status (open/closed)
  if (recruitPostMatch && request.method === 'PUT') {
    const teamId = recruitPostMatch[1];
    const postId = recruitPostMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    if (body.status) {
      await env.DB.prepare('UPDATE recruitment_posts SET status = ? WHERE id = ? AND team_id = ?').bind(body.status, postId, teamId).run();
    }
    return json({ ok: true });
  }

  // DELETE /api/teams/:id/recruitment/:postId
  if (recruitPostMatch && request.method === 'DELETE') {
    const teamId = recruitPostMatch[1];
    const postId = recruitPostMatch[2];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM recruitment_applications WHERE post_id = ?').bind(postId).run();
    await env.DB.prepare('DELETE FROM recruitment_posts WHERE id = ? AND team_id = ?').bind(postId, teamId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/recruitment/:postId/apply — apply to a post
  if (recruitApplyMatch && request.method === 'POST') {
    const teamId = recruitApplyMatch[1];
    const postId = recruitApplyMatch[2];

    const post = await env.DB.prepare('SELECT * FROM recruitment_posts WHERE id = ? AND team_id = ?').bind(postId, teamId).first();
    if (!post) return json({ error: 'Post not found' }, 404);
    if (post.status === 'closed') return json({ error: 'This position is closed' }, 400);

    // Check if already applied
    const existing = await env.DB.prepare('SELECT id FROM recruitment_applications WHERE post_id = ? AND user_id = ?').bind(postId, user.userId).first();
    if (existing) return json({ error: 'Already applied' }, 400);

    const body = await request.json();
    await env.DB.prepare('INSERT INTO recruitment_applications (id, post_id, user_id, message) VALUES (?, ?, ?, ?)')
      .bind(crypto.randomUUID(), postId, user.userId, (body.message || '').slice(0, 500)).run();

    return json({ ok: true });
  }

  // PUT /api/teams/:id/recruitment/:postId/applications/:appId — accept/reject
  if (recruitAppMatch && request.method === 'PUT') {
    const teamId = recruitAppMatch[1];
    const appId = recruitAppMatch[3];
    const member = await requireTeamMember(teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await request.json();
    if (body.status === 'accepted' || body.status === 'rejected') {
      await env.DB.prepare('UPDATE recruitment_applications SET status = ?, reviewed_by = ? WHERE id = ?')
        .bind(body.status, user.userId, appId).run();
    }
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handleRequest(request, env);
    } catch(e) {
      console.error('Unhandled error:', e);
      return new Response(JSON.stringify({ error: 'Internal server error', detail: e.message }), {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders() },
      });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleScheduled(env));
  },
};
