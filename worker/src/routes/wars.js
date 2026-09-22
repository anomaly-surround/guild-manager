// War log + inter-team match scheduling (protected routes)

import { json, safeJson } from '../lib/http.js';
import { sendDiscord } from '../lib/discord.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/wars$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/wars$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
    const warHook = settings?.webhook_wars || settings?.webhook_url;
    if (warHook && settings?.on_war !== 0) {
      const emoji = body.result === 'win' ? '🏆' : body.result === 'loss' ? '❌' : '🤝';
      const scoreText = body.scoreUs !== undefined && body.scoreThem !== undefined ? ` (${body.scoreUs}-${body.scoreThem})` : '';
      await sendDiscord(warHook, `War Result: ${body.result.toUpperCase()}`,
        `${emoji} **${body.result.toUpperCase()}** vs **${body.opponent.trim()}**${scoreText}${body.notes ? '\n' + body.notes : ''}`,
        body.result === 'win' ? 5763719 : body.result === 'loss' ? 15548997 : 16760576);
    }

    return json({ ok: true, id });
  } },

  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/wars\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, warId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    await env.DB.prepare('DELETE FROM war_log WHERE id = ? AND team_id = ?').bind(warId, teamId).run();
    return json({ ok: true });
  } },

  // GET /api/teams/:id/matches — list all matches (sent & received)
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/matches$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const matches = await env.DB.prepare(`
      SELECT m.*, u.username as created_by_name FROM matches m
      LEFT JOIN users u ON u.id = m.created_by
      WHERE m.challenger_team_id = ? OR m.challenged_team_id = ?
      ORDER BY m.created_at DESC LIMIT 50
    `).bind(teamId, teamId).all();

    return json({ matches: matches.results });
  } },

  // POST /api/teams/:id/matches — send challenge
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/matches$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.opponentTeamId) return json({ error: 'Opponent team required' }, 400);

    const myTeam = await env.DB.prepare('SELECT name FROM teams WHERE id = ?').bind(teamId).first();
    const oppTeam = await env.DB.prepare('SELECT name FROM teams WHERE id = ?').bind(body.opponentTeamId).first();
    if (!oppTeam) return json({ error: 'Opponent team not found' }, 404);

    const matchId = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO matches (id, challenger_team_id, challenged_team_id, challenger_name, challenged_name, match_type, scheduled_time, message, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(matchId, teamId, body.opponentTeamId, myTeam.name, oppTeam.name, body.matchType || 'gvg',
        body.scheduledTime || null, (body.message || '').slice(0, 200), user.userId).run();

    // Notify opponent via webhook
    const oppSettings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(body.opponentTeamId).first();
    const oppWarHook = oppSettings?.webhook_wars || oppSettings?.webhook_url;
    if (oppWarHook) {
      await sendDiscord(oppWarHook, 'New Match Challenge!',
        `**${myTeam.name}** has challenged your team to a **${body.matchType || 'gvg'}**!${body.message ? '\n> ' + body.message : ''}${body.scheduledTime ? '\nScheduled: <t:' + Math.floor(body.scheduledTime / 1000) + ':F>' : ''}`, 16760576);
    }

    return json({ ok: true, id: matchId });
  } },

  // POST /api/teams/:id/matches/:matchId/accept
  { method: '*', pattern: /^\/api\/teams\/([^/]+)\/matches\/([^/]+)\/accept$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const matchId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const match = await env.DB.prepare('SELECT * FROM matches WHERE id = ? AND challenged_team_id = ? AND status = ?').bind(matchId, teamId, 'pending').first();
    if (!match) return json({ error: 'Match not found or already responded' }, 404);

    await env.DB.prepare('UPDATE matches SET status = ? WHERE id = ?').bind('accepted', matchId).run();

    // Notify challenger
    const challengerSettings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(match.challenger_team_id).first();
    const challengerWarHook = challengerSettings?.webhook_wars || challengerSettings?.webhook_url;
    if (challengerWarHook) {
      await sendDiscord(challengerWarHook, 'Challenge Accepted!',
        `**${match.challenged_name}** accepted your match challenge!`, 5763719);
    }

    return json({ ok: true });
  } },

  // POST /api/teams/:id/matches/:matchId/decline
  { method: '*', pattern: /^\/api\/teams\/([^/]+)\/matches\/([^/]+)\/decline$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const matchId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const match = await env.DB.prepare('SELECT * FROM matches WHERE id = ? AND challenged_team_id = ? AND status = ?').bind(matchId, teamId, 'pending').first();
    if (!match) return json({ error: 'Match not found or already responded' }, 404);

    await env.DB.prepare('UPDATE matches SET status = ? WHERE id = ?').bind('declined', matchId).run();

    return json({ ok: true });
  } },

  // POST /api/teams/:id/matches/:matchId/result — log result (either team can do this)
  { method: '*', pattern: /^\/api\/teams\/([^/]+)\/matches\/([^/]+)\/result$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const matchId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const match = await env.DB.prepare('SELECT * FROM matches WHERE id = ? AND status = ? AND (challenger_team_id = ? OR challenged_team_id = ?)')
      .bind(matchId, 'accepted', teamId, teamId).first();
    if (!match) return json({ error: 'Match not found or not accepted' }, 404);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    const scoreCh = body.scoreChallenger !== undefined ? parseInt(body.scoreChallenger) : null;
    const scoreCd = body.scoreChallenged !== undefined ? parseInt(body.scoreChallenged) : null;

    let winnerId = null;
    if (scoreCh !== null && scoreCd !== null) {
      if (scoreCh > scoreCd) winnerId = match.challenger_team_id;
      else if (scoreCd > scoreCh) winnerId = match.challenged_team_id;
    }

    await env.DB.prepare('UPDATE matches SET status = ?, result_challenger = ?, result_challenged = ?, winner_team_id = ?, completed_by = ? WHERE id = ?')
      .bind('completed', scoreCh, scoreCd, winnerId, user.userId, matchId).run();

    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/matches/:matchId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/matches\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const matchId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    // Only allow deleting if this team is involved
    await env.DB.prepare('DELETE FROM matches WHERE id = ? AND (challenger_team_id = ? OR challenged_team_id = ?)')
      .bind(matchId, teamId, teamId).run();

    return json({ ok: true });
  } },
];
