// Loot rotation (protected routes): the ordered member list, officer moves, leader reset.
// Logging loot moves the recipient to the bottom — that lives in routes/loot.js.

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';
import { lootModeFor, moveMember, ROTATION_ORDER_SQL } from '../lib/rotation.js';

export const routes = [
  // GET /api/teams/:id/rotation — members in rotation order, with each one's latest drop
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/rotation$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const rows = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar, u.discord_id, tm.role, tm.game_role, tm.loot_pos, tm.joined_at,
        (SELECT bl.item_name FROM boss_loot bl WHERE bl.team_id = tm.team_id AND bl.recipient_id = tm.user_id ORDER BY bl.created_at DESC LIMIT 1) AS last_item,
        (SELECT bl.created_at FROM boss_loot bl WHERE bl.team_id = tm.team_id AND bl.recipient_id = tm.user_id ORDER BY bl.created_at DESC LIMIT 1) AS last_at
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = ?
      ${ROTATION_ORDER_SQL}
    `).bind(teamId).all();

    return json({ mode: await lootModeFor(env, teamId), order: rows.results });
  } },

  // POST /api/teams/:id/rotation/reset — leader: forget every position (back to join order)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/rotation\/reset$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role !== 'leader') return json({ error: 'Leader only' }, 403);
    await env.DB.prepare('UPDATE team_members SET loot_pos = NULL WHERE team_id = ?').bind(teamId).run();
    return json({ ok: true });
  } },

  // POST /api/teams/:id/rotation/:userId { to: 'top'|'bottom'|'up'|'down' } — officers+
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/rotation\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, userId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body || !['top', 'bottom', 'up', 'down'].includes(body.to)) return json({ error: 'to must be top, bottom, up or down' }, 400);
    const ok = await moveMember(env, teamId, userId, body.to);
    if (!ok) return json({ error: 'Not a member of this team' }, 404);
    return json({ ok: true });
  } },
];
