// Polls (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/polls
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/polls$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
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
  } },

  // POST /api/teams/:id/polls — create poll
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/polls$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.question || !body.options || body.options.length < 2) return json({ error: 'Question and at least 2 options required' }, 400);

    const pollId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO polls (id, team_id, question, poll_type, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(pollId, teamId, body.question.slice(0, 200), body.pollType || 'single', user.userId, body.expiresAt || null).run();

    for (let i = 0; i < body.options.length && i < 10; i++) {
      await env.DB.prepare('INSERT INTO poll_options (id, poll_id, label, sort_order) VALUES (?, ?, ?, ?)')
        .bind(crypto.randomUUID(), pollId, body.options[i].slice(0, 100), i).run();
    }

    return json({ ok: true, id: pollId });
  } },

  // POST /api/teams/:id/polls/:pollId/vote
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/polls\/([^/]+)\/vote$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const pollId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const poll = await env.DB.prepare('SELECT * FROM polls WHERE id = ? AND team_id = ?').bind(pollId, teamId).first();
    if (!poll) return json({ error: 'Poll not found' }, 404);
    if (poll.closed) return json({ error: 'Poll is closed' }, 400);
    if (poll.expires_at && poll.expires_at < Math.floor(Date.now() / 1000)) return json({ error: 'Poll has expired' }, 400);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
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
  } },

  // POST /api/teams/:id/polls/:pollId/close
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/polls\/([^/]+)\/close$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const pollId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('UPDATE polls SET closed = 1 WHERE id = ? AND team_id = ?').bind(pollId, teamId).run();
    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/polls/:pollId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/polls\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const pollId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM poll_votes WHERE poll_id = ?').bind(pollId).run();
    await env.DB.prepare('DELETE FROM poll_options WHERE poll_id = ?').bind(pollId).run();
    await env.DB.prepare('DELETE FROM polls WHERE id = ? AND team_id = ?').bind(pollId, teamId).run();
    return json({ ok: true });
  } },
];
