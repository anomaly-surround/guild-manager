// Events, RSVPs, attendance, event templates, attendance report (protected routes)

import { json, safeJson } from '../lib/http.js';
import { sendDiscord } from '../lib/discord.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/events
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/events$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  // POST /api/teams/:id/events — create event
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/events$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    // Check if members can create events
    if (member.role === 'member') {
      const ts = await env.DB.prepare('SELECT members_create_events FROM team_settings WHERE team_id = ?').bind(teamId).first();
      if (ts && !ts.members_create_events) return json({ error: 'Only officers+ can create events' }, 403);
    }

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
    const eventHook = settings?.webhook_events || settings?.webhook_url;
    if (eventHook) {
      const date = new Date(body.eventTime).toLocaleString('en-US', { timeZone: settings.timezone || 'Asia/Manila' });
      await sendDiscord(eventHook, `New Event: ${body.title}`,
        `**${body.title}** scheduled for **${date}**\nCreated by ${user.username}${body.description ? '\n\n' + body.description : ''}`,
        5793266);
    }

    return json({ ok: true, id });
  } },

  // DELETE /api/teams/:id/events/:eventId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/events\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, eventId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  // POST /api/teams/:id/events/:eventId/rsvp
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/events\/([^/]+)\/rsvp$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, eventId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  // GET /api/teams/:id/events/:eventId/rsvps — get RSVP details
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/events\/([^/]+)\/rsvps$/, handler: async ({ env, user, params }) => {
    const [, teamId, eventId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const rsvps = await env.DB.prepare(`
      SELECT u.username, u.avatar, u.discord_id, r.status
      FROM event_rsvps r JOIN users u ON u.id = r.user_id
      WHERE r.event_id = ? ORDER BY r.responded_at ASC
    `).bind(eventId).all();

    return json({ rsvps: rsvps.results });
  } },

  // POST /api/teams/:id/events/:eventId/attendance — mark attendance (officers+)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/events\/([^/]+)\/attendance$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, eventId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  // GET /api/teams/:id/events/:eventId/attendance
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/events\/([^/]+)\/attendance$/, handler: async ({ env, user, params }) => {
    const [, teamId, eventId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const attendance = await env.DB.prepare(`
      SELECT u.username, u.avatar, u.discord_id, a.attended
      FROM event_attendance a JOIN users u ON u.id = a.user_id
      WHERE a.event_id = ?
    `).bind(eventId).all();

    return json({ attendance: attendance.results });
  } },

  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/event-templates$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const templates = await env.DB.prepare('SELECT * FROM event_templates WHERE team_id = ? ORDER BY name')
      .bind(teamId).all();
    return json({ templates: templates.results });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/event-templates$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.name?.trim() || !body.title?.trim()) return json({ error: 'Name and title required' }, 400);
    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO event_templates (id, team_id, name, title, description, event_type, duration_minutes, recurrence, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.name.trim(), body.title.trim(), body.description || null, body.eventType || 'other', body.durationMinutes || 60, body.recurrence || null, user.userId).run();
    return json({ ok: true, id });
  } },

  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/event-templates\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, templateId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    await env.DB.prepare('DELETE FROM event_templates WHERE id = ? AND team_id = ?').bind(templateId, teamId).run();
    return json({ ok: true });
  } },

  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/attendance-report$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

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
  } },
];
