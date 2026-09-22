// Boss timers, kills, templates, kill history (protected routes)

import { json, safeJson } from '../lib/http.js';
import { getNextFixedSpawn, getNextWeeklySpawn, getNextBiweeklySpawn, getNextTwiceDailySpawn, calcNextSpawn } from '../lib/spawn.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/bosses
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/bosses$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const bosses = await env.DB.prepare('SELECT * FROM bosses WHERE team_id = ? ORDER BY next_spawn ASC')
      .bind(teamId).all();
    return json({ bosses: bosses.results });
  } },

  // POST /api/teams/:id/bosses — add boss
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/bosses$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (member.role === 'member') {
      // Members can add bosses too — officers+ can delete
    }

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.name?.trim()) return json({ error: 'Name required' }, 400);
    if (body.name.trim().length > 100) return json({ error: 'Name too long (max 100 chars)' }, 400);

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
    } else if (body.type === 'twicedaily') {
      nextSpawn = getNextTwiceDailySpawn(body.twiceDailyTimes, tz);
    }

    // Suppress immediate warning if inside alert window
    const alertMs = (body.alertMinutes || 5) * 60000;
    const warned = (nextSpawn - Date.now()) <= alertMs ? 1 : 0;

    const windowMs = Math.max(0, Math.min(86400000, parseInt(body.windowMs) || 0));
    const location = body.location ? String(body.location).trim().slice(0, 80) : null;
    await env.DB.prepare(`INSERT INTO bosses (id, team_id, name, type, interval_ms, fixed_time, weekly_day, weekly_time, biweekly_days, alert_minutes, auto_reset_minutes, next_spawn, warned, window_ms, location) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(id, teamId, body.name.trim(), body.type,
        body.intervalMs || null, body.fixedTime || null,
        body.weeklyDay ?? null, body.weeklyTime || null,
        body.biweeklyDays ? JSON.stringify(body.biweeklyDays) : body.twiceDailyTimes ? JSON.stringify(body.twiceDailyTimes) : null,
        body.alertMinutes || 5, body.autoResetMinutes || 5, nextSpawn, warned, windowMs, location).run();

    return json({ ok: true, id });
  } },

  // POST /api/teams/:id/bosses/:bossId/kill
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/bosses\/([^/]+)\/kill$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, bossId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await request.json().catch(() => ({}));
    const deathTime = Number(body.deathTime) || Date.now();
    if (deathTime < 0 || deathTime > Date.now() + 86400000) return json({ error: 'Invalid death time' }, 400);

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
  } },

  // PUT /api/teams/:id/bosses/:bossId — edit a boss (officers+). Schedule changes recompute next_spawn.
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/bosses\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, bossId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    const boss = await env.DB.prepare('SELECT * FROM bosses WHERE id = ? AND team_id = ?').bind(bossId, teamId).first();
    if (!boss) return json({ error: 'Boss not found' }, 404);

    const sets = [], vals = [];
    if (body.name !== undefined) {
      const name = String(body.name).trim();
      if (!name) return json({ error: 'Name required' }, 400);
      if (name.length > 100) return json({ error: 'Name too long (max 100 chars)' }, 400);
      sets.push('name = ?'); vals.push(name);
    }
    if (body.location !== undefined) { sets.push('location = ?'); vals.push(body.location ? String(body.location).trim().slice(0, 80) : null); }
    if (body.alertMinutes !== undefined) { sets.push('alert_minutes = ?'); vals.push(Math.max(1, Math.min(1440, parseInt(body.alertMinutes) || 5))); }
    if (body.autoResetMinutes !== undefined) { sets.push('auto_reset_minutes = ?'); vals.push(Math.max(1, Math.min(1440, parseInt(body.autoResetMinutes) || 5))); }
    if (body.windowMs !== undefined) { sets.push('window_ms = ?'); vals.push(Math.max(0, Math.min(86400000, parseInt(body.windowMs) || 0))); }

    const scheduleChanged = body.type !== undefined || body.intervalMs !== undefined || body.fixedTime !== undefined ||
      body.weeklyDay !== undefined || body.weeklyTime !== undefined || body.biweeklyDays !== undefined || body.twiceDailyTimes !== undefined;
    if (scheduleChanged) {
      const type = body.type || boss.type;
      const settings = await env.DB.prepare('SELECT timezone FROM team_settings WHERE team_id = ?').bind(teamId).first();
      const tz = settings?.timezone || 'Asia/Manila';
      const intervalMs = body.intervalMs ?? boss.interval_ms;
      const fixedTime = body.fixedTime ?? boss.fixed_time;
      const weeklyDay = body.weeklyDay ?? boss.weekly_day;
      const weeklyTime = body.weeklyTime ?? boss.weekly_time;
      const days = body.biweeklyDays ? JSON.stringify(body.biweeklyDays) : body.twiceDailyTimes ? JSON.stringify(body.twiceDailyTimes) : boss.biweekly_days;
      let nextSpawn;
      if (type === 'interval') {
        if (!intervalMs) return json({ error: 'Interval required' }, 400);
        nextSpawn = (boss.last_death || Date.now()) + intervalMs;
        if (nextSpawn < Date.now()) nextSpawn = Date.now() + intervalMs;
      } else if (type === 'fixed') nextSpawn = getNextFixedSpawn(fixedTime, tz);
      else if (type === 'weekly') nextSpawn = getNextWeeklySpawn(weeklyDay, weeklyTime, tz);
      else if (type === 'biweekly') nextSpawn = getNextBiweeklySpawn(days, tz);
      else if (type === 'twicedaily') nextSpawn = getNextTwiceDailySpawn(days, tz);
      else return json({ error: 'Invalid type' }, 400);
      sets.push('type = ?', 'interval_ms = ?', 'fixed_time = ?', 'weekly_day = ?', 'weekly_time = ?', 'biweekly_days = ?', 'next_spawn = ?', "status = 'waiting'", 'spawned_at = NULL', 'auto_reset_at = NULL', 'warned = 0', 'spawn_notified = 0');
      vals.push(type, type === 'interval' ? intervalMs : null, type === 'fixed' ? fixedTime : null, type === 'weekly' ? weeklyDay : null, type === 'weekly' ? weeklyTime : null, (type === 'biweekly' || type === 'twicedaily') ? days : null, nextSpawn);
    }
    if (sets.length === 0) return json({ ok: true });
    vals.push(bossId);
    await env.DB.prepare(`UPDATE bosses SET ${sets.join(', ')} WHERE id = ?`).bind(...vals).run();
    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/bosses/:bossId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/bosses\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, bossId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    await env.DB.prepare('DELETE FROM bosses WHERE id = ? AND team_id = ?').bind(bossId, teamId).run();
    return json({ ok: true });
  } },

  { method: 'GET', pattern: '/api/boss-templates', handler: async ({ env, user }) => {
    const templates = await env.DB.prepare('SELECT * FROM boss_templates WHERE is_global = 1 OR created_by = ? ORDER BY game, name')
      .bind(user.userId).all();
    return json({ templates: templates.results });
  } },

  { method: 'POST', pattern: '/api/boss-templates', handler: async ({ request, env, user }) => {
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.name?.trim() || !body.game?.trim() || !body.bosses) return json({ error: 'Name, game, and bosses required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO boss_templates (id, name, game, bosses, created_by) VALUES (?, ?, ?, ?, ?)')
      .bind(id, body.name.trim(), body.game.trim(), JSON.stringify(body.bosses), user.userId).run();
    return json({ ok: true, id });
  } },

  { method: 'DELETE', pattern: /^\/api\/boss-templates\/([^/]+)$/, handler: async ({ env, user, params }) => {
    await env.DB.prepare('DELETE FROM boss_templates WHERE id = ? AND created_by = ?')
      .bind(params[1], user.userId).run();
    return json({ ok: true });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/bosses\/import-template$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/bosses\/history$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

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
  } },
];
