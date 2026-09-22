// Member notes, activity heartbeat, availability (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET/POST /api/teams/:id/members/:userId/notes
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/members\/([^/]+)\/notes$/, handler: async ({ env, user, params }) => {
    const [, teamId, targetUserId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const notes = await env.DB.prepare(`
      SELECT n.*, u.username as author_name
      FROM member_notes n JOIN users u ON u.id = n.author_id
      WHERE n.team_id = ? AND n.target_user_id = ?
      ORDER BY n.created_at DESC
    `).bind(teamId, targetUserId).all();

    return json({ notes: notes.results });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/members\/([^/]+)\/notes$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, targetUserId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.note?.trim()) return json({ error: 'Note required' }, 400);
    if (body.note.trim().length > 1000) return json({ error: 'Note too long (max 1000 chars)' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO member_notes (id, team_id, target_user_id, author_id, note) VALUES (?, ?, ?, ?, ?)')
      .bind(id, teamId, targetUserId, user.userId, body.note.trim()).run();
    return json({ ok: true, id });
  } },

  // DELETE /api/teams/:id/notes/:noteId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/notes\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, noteId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const note = await env.DB.prepare('SELECT * FROM member_notes WHERE id = ? AND team_id = ?').bind(noteId, teamId).first();
    if (!note) return json({ error: 'Not found' }, 404);
    if (note.author_id !== user.userId && member.role !== 'leader') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM member_notes WHERE id = ?').bind(noteId).run();
    return json({ ok: true });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/heartbeat$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    await env.DB.prepare('INSERT OR REPLACE INTO member_activity (team_id, user_id, last_seen) VALUES (?, ?, unixepoch())')
      .bind(teamId, user.userId).run();
    return json({ ok: true });
  } },

  // GET /api/teams/:id/availability — get all members' availability
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/availability$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const slots = await env.DB.prepare(`
      SELECT ma.*, u.username
      FROM member_availability ma JOIN users u ON u.id = ma.user_id
      WHERE ma.team_id = ?
      ORDER BY ma.day, ma.start_time
    `).bind(teamId).all();

    return json({ slots: slots.results });
  } },

  // PUT /api/teams/:id/availability — set my availability (replaces all my slots)
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/availability$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    // body.slots = [{day: 0-6, startTime: "HH:MM", endTime: "HH:MM"}, ...]
    await env.DB.prepare('DELETE FROM member_availability WHERE team_id = ? AND user_id = ?')
      .bind(teamId, user.userId).run();

    for (const slot of (body.slots || [])) {
      if (slot.day === undefined || !slot.startTime || !slot.endTime) continue;
      await env.DB.prepare('INSERT INTO member_availability (team_id, user_id, day, start_time, end_time) VALUES (?, ?, ?, ?, ?)')
        .bind(teamId, user.userId, slot.day, slot.startTime, slot.endTime).run();
    }

    return json({ ok: true });
  } },
];
