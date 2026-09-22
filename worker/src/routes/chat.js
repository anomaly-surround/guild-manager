// Team chat + reactions (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';

export const routes = [
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/chat$/, handler: async ({ env, url, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const after = url.searchParams.get('after') || '0';

    const messages = await env.DB.prepare(`
      SELECT cm.*, u.username, u.avatar, u.discord_id
      FROM chat_messages cm JOIN users u ON u.id = cm.user_id
      WHERE cm.team_id = ? AND cm.created_at > ?
      ORDER BY cm.created_at ASC
      LIMIT 100
    `).bind(teamId, parseInt(after)).all();

    // Attach reactions
    const msgIds = messages.results.map(m => m.id);
    if (msgIds.length > 0) {
      const reactions = await env.DB.prepare(
        `SELECT * FROM chat_reactions WHERE message_id IN (${msgIds.map(() => '?').join(',')})`)
        .bind(...msgIds).all().catch(() => ({ results: [] }));
      const reactionMap = {};
      for (const r of reactions.results) {
        if (!reactionMap[r.message_id]) reactionMap[r.message_id] = [];
        reactionMap[r.message_id].push(r);
      }
      for (const m of messages.results) m.reactions = reactionMap[m.id] || [];
    }

    return json({ messages: messages.results });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/chat$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.message?.trim()) return json({ error: 'Message required' }, 400);
    if (body.message.length > 2000) return json({ error: 'Message too long' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO chat_messages (id, team_id, user_id, message) VALUES (?, ?, ?, ?)')
      .bind(id, teamId, user.userId, body.message.trim()).run();

    return json({ ok: true, id });
  } },

  // DELETE single message (author or officers+)
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/chat\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, msgId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const msg = await env.DB.prepare('SELECT * FROM chat_messages WHERE id = ? AND team_id = ?').bind(msgId, teamId).first();
    if (!msg) return json({ error: 'Not found' }, 404);
    if (msg.user_id !== user.userId && member.role === 'member') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM chat_messages WHERE id = ?').bind(msgId).run();
    return json({ ok: true });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/chat\/([^/]+)\/react$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, msgId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.emoji) return json({ error: 'Emoji required' }, 400);

    const existing = await env.DB.prepare('SELECT 1 FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
      .bind(msgId, user.userId, body.emoji).first();
    if (existing) {
      await env.DB.prepare('DELETE FROM chat_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?')
        .bind(msgId, user.userId, body.emoji).run();
    } else {
      await env.DB.prepare('INSERT INTO chat_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)')
        .bind(msgId, user.userId, body.emoji).run();
    }
    return json({ ok: true });
  } },
];
