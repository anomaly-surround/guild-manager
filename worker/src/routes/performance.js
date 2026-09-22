// Performance tracker (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/performance
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/performance$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  // POST /api/teams/:id/performance — log stats
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/performance$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.userId || !body.eventLabel || !body.stats || !Array.isArray(body.stats)) return json({ error: 'userId, eventLabel, and stats[] required' }, 400);

    for (const stat of body.stats.slice(0, 20)) {
      if (!stat.name || stat.value === undefined) continue;
      await env.DB.prepare('INSERT INTO performance_entries (id, team_id, user_id, event_label, stat_name, stat_value, logged_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(crypto.randomUUID(), teamId, body.userId, body.eventLabel.slice(0, 100), stat.name.slice(0, 50), Number(stat.value) || 0, user.userId).run();
    }

    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/performance/:entryId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/performance\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const entryId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM performance_entries WHERE id = ? AND team_id = ?').bind(entryId, teamId).run();
    return json({ ok: true });
  } },
];
