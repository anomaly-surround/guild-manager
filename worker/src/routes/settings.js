// Team settings, webhook test, custom role names (protected routes)

import { json, safeJson } from '../lib/http.js';
import { rateLimit } from '../lib/ratelimit.js';
import { sendDiscord, isValidDiscordWebhook } from '../lib/discord.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';
import { parseRoles } from './events.js';

export const routes = [
  // GET /api/teams/:id/settings
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/settings$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    return json({
      webhookUrlSet: !!settings?.webhook_url,
      onWarning: settings?.on_warning ?? true,
      onSpawn: settings?.on_spawn ?? true,
      onEvent: settings?.on_event ?? true,
      eventReminderMinutes: settings?.event_reminder_minutes ?? 15,
      inactiveDays: settings?.inactive_days ?? 7,
      defaultEventDuration: settings?.default_event_duration ?? 60,
      teamDescription: settings?.team_description || '',
      membersCreateEvents: settings?.members_create_events ?? true,
      autoDeleteEventsDays: settings?.auto_delete_events_days ?? 0,
      startingDkp: settings?.starting_dkp ?? 0,
      timezone: settings?.timezone || 'Asia/Manila',
      // Premium settings — only return "set" flags, never leak the URL (even partially)
      webhookBossSet: !!settings?.webhook_boss,
      webhookEventsSet: !!settings?.webhook_events,
      dkpDecayEnabled: !!(settings?.dkp_decay_enabled),
      dkpDecayPercent: settings?.dkp_decay_percent ?? 10,
      dkpDecayInactiveDays: settings?.dkp_decay_inactive_days ?? 14,
      dkpDecayIntervalDays: settings?.dkp_decay_interval_days ?? 7,
      accentColor: settings?.accent_color || '',
      teamIcon: settings?.team_icon || '',
      invitesEnabled: settings?.invites_enabled ?? true,
      inviteApproval: !!(settings?.invite_approval),
      publicToken: settings?.public_token || null,
      rsvpRoles: parseRoles(settings?.rsvp_roles),
      modules: (() => { try { return settings?.modules ? JSON.parse(settings.modules) : {}; } catch { return {}; } })(),
    });
  } },

  // PUT /api/teams/:id/settings
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/settings$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) {
      return json({ error: 'Officers+ only' }, 403);
    }

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    let existingRow = await env.DB.prepare('SELECT modules FROM team_settings WHERE team_id = ?').bind(teamId).first();
    let existing = existingRow;
    if (!existing) {
      // First save for this team: create the row, then apply every field through the update path below.
      await env.DB.prepare('INSERT INTO team_settings (team_id, timezone) VALUES (?, ?)').bind(teamId, body.timezone || 'Asia/Manila').run();
      existing = true;
    }

    if (existing) {
      const sets = [];
      const vals = [];
      if (body.webhookUrl !== undefined) {
        if (body.webhookUrl && !isValidDiscordWebhook(body.webhookUrl)) return json({ error: 'Webhook must be a Discord webhook URL (https://discord.com/api/webhooks/...)' }, 400);
        sets.push('webhook_url = ?'); vals.push(body.webhookUrl || null);
      }
      if (body.onWarning !== undefined) { sets.push('on_warning = ?'); vals.push(body.onWarning ? 1 : 0); }
      if (body.onSpawn !== undefined) { sets.push('on_spawn = ?'); vals.push(body.onSpawn ? 1 : 0); }
      if (body.onEvent !== undefined) { sets.push('on_event = ?'); vals.push(body.onEvent ? 1 : 0); }
      if (body.eventReminderMinutes !== undefined) { sets.push('event_reminder_minutes = ?'); vals.push(body.eventReminderMinutes); }
      if (body.inactiveDays !== undefined) { sets.push('inactive_days = ?'); vals.push(body.inactiveDays); }
      if (body.defaultEventDuration !== undefined) { sets.push('default_event_duration = ?'); vals.push(body.defaultEventDuration); }
      if (body.teamDescription !== undefined) { sets.push('team_description = ?'); vals.push(body.teamDescription || null); }
      if (body.invitesEnabled !== undefined) {
        if (member.role !== 'leader') return json({ error: 'Only the leader can change invite settings' }, 403);
        sets.push('invites_enabled = ?'); vals.push(body.invitesEnabled ? 1 : 0);
      }
      if (body.inviteApproval !== undefined) {
        if (member.role !== 'leader') return json({ error: 'Only the leader can change invite settings' }, 403);
        sets.push('invite_approval = ?'); vals.push(body.inviteApproval ? 1 : 0);
      }
      if (body.modules !== undefined && typeof body.modules === 'object') {
        const cur = (() => { try { return JSON.parse(existingRow?.modules || '{}'); } catch { return {}; } })();
        const next = { ...cur };
        if (body.modules.points !== undefined) next.points = !!body.modules.points;
        sets.push('modules = ?'); vals.push(JSON.stringify(next));
      }
      if (body.rsvpRoles !== undefined) {
        const list = Array.isArray(body.rsvpRoles) ? body.rsvpRoles.map(r => String(r).trim().slice(0, 20)).filter(Boolean).slice(0, 8) : [];
        sets.push('rsvp_roles = ?'); vals.push(list.length ? JSON.stringify(list) : null);
      }
      if (body.publicTimers !== undefined) {
        if (body.publicTimers && !(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);
        sets.push('public_token = ?'); vals.push(body.publicTimers ? crypto.randomUUID().replace(/-/g, '') : null);
      }
      if (body.membersCreateEvents !== undefined) { sets.push('members_create_events = ?'); vals.push(body.membersCreateEvents ? 1 : 0); }
      if (body.autoDeleteEventsDays !== undefined) { sets.push('auto_delete_events_days = ?'); vals.push(body.autoDeleteEventsDays); }
      if (body.startingDkp !== undefined) { sets.push('starting_dkp = ?'); vals.push(body.startingDkp); }
      if (body.timezone !== undefined) { sets.push('timezone = ?'); vals.push(body.timezone); }
      // Premium fields — require premium team
      const hasPremiumFields = body.webhookBoss !== undefined || body.webhookEvents !== undefined ||
        body.dkpDecayEnabled !== undefined || body.dkpDecayPercent !== undefined ||
        body.dkpDecayInactiveDays !== undefined || body.dkpDecayIntervalDays !== undefined;

      if (hasPremiumFields && !(await isPremiumTeam(env, teamId))) {
        return json({ error: 'Premium required', premiumRequired: true }, 403);
      }

      if (body.webhookBoss !== undefined) {
        if (body.webhookBoss && !isValidDiscordWebhook(body.webhookBoss)) return json({ error: 'Invalid Discord webhook URL' }, 400);
        sets.push('webhook_boss = ?'); vals.push(body.webhookBoss || null);
      }
      if (body.webhookEvents !== undefined) {
        if (body.webhookEvents && !isValidDiscordWebhook(body.webhookEvents)) return json({ error: 'Invalid Discord webhook URL' }, 400);
        sets.push('webhook_events = ?'); vals.push(body.webhookEvents || null);
      }
      if (body.dkpDecayEnabled !== undefined) { sets.push('dkp_decay_enabled = ?'); vals.push(body.dkpDecayEnabled ? 1 : 0); }
      if (body.dkpDecayPercent !== undefined) { sets.push('dkp_decay_percent = ?'); vals.push(Math.min(100, Math.max(0, parseInt(body.dkpDecayPercent) || 10))); }
      if (body.dkpDecayInactiveDays !== undefined) { sets.push('dkp_decay_inactive_days = ?'); vals.push(Math.min(365, Math.max(1, parseInt(body.dkpDecayInactiveDays) || 14))); }
      if (body.dkpDecayIntervalDays !== undefined) { sets.push('dkp_decay_interval_days = ?'); vals.push(Math.min(90, Math.max(1, parseInt(body.dkpDecayIntervalDays) || 7))); }
      if (body.accentColor !== undefined) { sets.push('accent_color = ?'); vals.push(body.accentColor || null); }
      if (body.teamIcon !== undefined) { sets.push('team_icon = ?'); vals.push(body.teamIcon || null); }
      if (sets.length > 0) {
        vals.push(teamId);
        await env.DB.prepare(`UPDATE team_settings SET ${sets.join(', ')} WHERE team_id = ?`).bind(...vals).run();
      }
    }

    return json({ ok: true });
  } },

  // POST /api/teams/:id/settings/test — test webhook (leader/officer only)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/settings\/test$/, handler: async ({ env, user, params }) => {
    if (rateLimit(`webhook-test:${user.userId}`, 3, 60000)) {
      return json({ error: 'Too many test requests. Try again in a minute.' }, 429);
    }
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    const settings = await env.DB.prepare('SELECT webhook_url FROM team_settings WHERE team_id = ?').bind(teamId).first();
    if (!settings?.webhook_url) return json({ error: 'No webhook' }, 400);
    await sendDiscord(settings.webhook_url, 'Test Notification', 'Guild Manager webhook is working!', 5793266);
    return json({ ok: true });
  } },

  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/roles$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const roles = await env.DB.prepare('SELECT * FROM custom_roles WHERE team_id = ?').bind(teamId).all();
    const roleMap = {};
    for (const r of roles.results) roleMap[r.base_role] = { displayName: r.display_name, color: r.color };
    return json({ roles: roleMap });
  } },

  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/roles$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role !== 'leader') return json({ error: 'Leader only' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    // body.roles = { leader: {displayName, color}, officer: {...}, member: {...} }
    await env.DB.prepare('DELETE FROM custom_roles WHERE team_id = ?').bind(teamId).run();
    for (const [role, data] of Object.entries(body.roles || {})) {
      if (['leader', 'officer', 'member'].includes(role) && data.displayName?.trim()) {
        await env.DB.prepare('INSERT INTO custom_roles (team_id, base_role, display_name, color) VALUES (?, ?, ?, ?)')
          .bind(teamId, role, data.displayName.trim(), data.color || null).run();
      }
    }
    return json({ ok: true });
  } },
];
