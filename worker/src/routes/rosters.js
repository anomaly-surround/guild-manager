// Rosters + slots (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/rosters
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/rosters$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  // POST /api/teams/:id/rosters — create roster
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/rosters$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  // PUT /api/teams/:id/rosters/:rosterId/slots — update all slots
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/rosters\/([^/]+)\/slots$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const rosterId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    await env.DB.prepare('DELETE FROM roster_slots WHERE roster_id = ?').bind(rosterId).run();

    for (let i = 0; i < (body.slots || []).length && i < 30; i++) {
      const s = body.slots[i];
      await env.DB.prepare('INSERT INTO roster_slots (id, roster_id, role_name, user_id, sort_order) VALUES (?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), rosterId, (s.roleName || 'Member').slice(0, 50), s.userId || null, i).run();
    }

    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/rosters/:rosterId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/rosters\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const rosterId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM roster_slots WHERE roster_id = ?').bind(rosterId).run();
    await env.DB.prepare('DELETE FROM rosters WHERE id = ? AND team_id = ?').bind(rosterId, teamId).run();
    return json({ ok: true });
  } },
];
