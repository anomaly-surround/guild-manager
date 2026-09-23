// Team CRUD, membership roles, kick/leave/transfer, team search (protected routes)

import { json, safeJson } from '../lib/http.js';
import { generateInviteCode } from '../lib/ids.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';
import { limitsFor, limitsJson } from '../lib/limits.js';
import { teamDeleteStmts } from '../lib/team-delete.js';
import { lootModeFor } from '../lib/rotation.js';

export const routes = [
  // GET /api/teams — list user's teams
  { method: 'GET', pattern: '/api/teams', handler: async ({ env, user }) => {
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
  } },

  // POST /api/teams — create a team
  { method: 'POST', pattern: '/api/teams', handler: async ({ request, env, user }) => {
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.name || !body.name.trim()) return json({ error: 'Name required' }, 400);

    // Check team limit (free = 1, premium = unlimited)
    const dbUser = await env.DB.prepare('SELECT premium, auth_type FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser || dbUser.auth_type === 'deleted') return json({ error: 'Account deleted' }, 401);
    const isPremium = dbUser?.premium;
    const teamCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM teams WHERE owner_id = ?'
    ).bind(user.userId).first();
    const teamCap = limitsFor(!!isPremium).teams;
    if (teamCount.count >= teamCap) {
      return json({ error: `Free plan: ${teamCap} team max. Upgrade for more.`, premiumRequired: true }, 403);
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
  } },

  // GET /api/teams/:id — team detail with members
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];

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
    const premiumTeam = await isPremiumTeam(env, teamId);

    const members = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar, u.discord_id, u.premium, tm.role, tm.joined_at, tm.game_role,
        ma.last_seen
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      LEFT JOIN member_activity ma ON ma.team_id = tm.team_id AND ma.user_id = tm.user_id
      WHERE tm.team_id = ?
      ORDER BY
        CASE tm.role WHEN 'leader' THEN 0 WHEN 'officer' THEN 1 ELSE 2 END,
        tm.joined_at ASC
    `).bind(teamId).all();

    // Module toggles: Loot & Points is off by default, unless the team already has loot/points data.
    const settingsRow = await env.DB.prepare('SELECT modules, loot_mode, timezone FROM team_settings WHERE team_id = ?').bind(teamId).first();
    let modules = null;
    try { modules = settingsRow?.modules ? JSON.parse(settingsRow.modules) : null; } catch {}
    const modeSet = settingsRow?.loot_mode === 'dkp' || settingsRow?.loot_mode === 'rotation';
    let used = null;
    if (!modules || modules.points === undefined || !modeSet) {
      used = await env.DB.prepare('SELECT (SELECT COUNT(*) FROM dkp_ledger WHERE team_id = ?) AS dkp, (SELECT COUNT(*) FROM boss_loot WHERE team_id = ?) AS loot').bind(teamId, teamId).first();
    }
    if (!modules || modules.points === undefined) modules = { ...(modules || {}), points: ((used?.dkp || 0) + (used?.loot || 0)) > 0 };
    const lootMode = await lootModeFor(env, teamId, settingsRow || null, used?.dkp ?? 0);

    return json({
      team: { ...team, my_role: membership.role, premium_team: premiumTeam, modules, loot_mode: lootMode, timezone: settingsRow?.timezone || 'Asia/Manila', max_members: limitsJson(premiumTeam).members, limits: limitsJson(premiumTeam) },
      members: members.results,
    });
  } },

  // DELETE /api/teams/:id — delete team (leader only)
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ? AND owner_id = ?')
      .bind(teamId, user.userId).first();
    if (!team) return json({ error: 'Not the owner' }, 403);

    await env.DB.batch(teamDeleteStmts(env, teamId));
    return json({ ok: true });
  } },

  // PUT /api/teams/:id/members/:userId — game role (self, or officers+ for anyone)
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/members\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, targetId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (targetId !== user.userId && member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (body.gameRole === undefined) return json({ ok: true });
    const gameRole = body.gameRole ? String(body.gameRole).trim().slice(0, 30) : null;
    const res = await env.DB.prepare('UPDATE team_members SET game_role = ? WHERE team_id = ? AND user_id = ?').bind(gameRole, teamId, targetId).run();
    if (!res.meta?.changes) return json({ error: 'User not in team' }, 404);
    return json({ ok: true });
  } },

  // POST /api/teams/:id/members/role — change member role (leader/officer only)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/members\/role$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.userId || !body.role) return json({ error: 'userId and role required' }, 400);

    // Prevent self-role-change
    if (body.userId === user.userId) return json({ error: 'Cannot change own role' }, 403);

    // Validate role value
    if (!['member', 'officer', 'leader'].includes(body.role)) return json({ error: 'Invalid role' }, 400);

    const myRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!myRole || (myRole.role !== 'leader' && myRole.role !== 'officer')) {
      return json({ error: 'No permission' }, 403);
    }

    // Verify target exists in team
    const targetRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, body.userId).first();
    if (!targetRole) return json({ error: 'User not in team' }, 400);

    // Only leader can promote to leader or officer
    if (body.role === 'leader' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can promote to leader' }, 403);
    }
    if (body.role === 'officer' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can promote to officer' }, 403);
    }

    // Officers can only demote members, not other officers
    if (myRole.role === 'officer' && targetRole.role !== 'member') {
      return json({ error: 'Officers can only manage members' }, 403);
    }

    await env.DB.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?')
      .bind(body.role, teamId, body.userId).run();
    return json({ ok: true });
  } },

  // POST /api/teams/:id/kick — kick member (leader/officer only)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/kick$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);

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
  } },

  // POST /api/teams/:id/leave — leave team
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/leave$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];

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
  } },

  // POST /api/teams/:id/transfer — transfer ownership (leader only)
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/transfer$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ? AND owner_id = ?')
      .bind(teamId, user.userId).first();
    if (!team) return json({ error: 'Not the owner' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  // GET /api/teams/:id/search-teams?q=name — search other teams by name
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/search-teams$/, handler: async ({ env, url, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const q = url.searchParams.get('q') || '';
    if (q.length < 2) return json({ teams: [] });

    const results = await env.DB.prepare(
      "SELECT id, name FROM teams WHERE name LIKE ? AND id != ? LIMIT 10"
    ).bind(`%${q}%`, teamId).all();

    return json({ teams: results.results });
  } },
];
