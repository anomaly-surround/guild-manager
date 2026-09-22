// Announcements + pinning (protected routes)

import { json, safeJson } from '../lib/http.js';
import { sendDiscord } from '../lib/discord.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET/POST /api/teams/:id/announcements
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/announcements$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const announcements = await env.DB.prepare(`
      SELECT a.*, u.username as author_name
      FROM announcements a JOIN users u ON u.id = a.created_by
      WHERE a.team_id = ?
      ORDER BY a.pinned DESC, a.created_at DESC
    `).bind(teamId).all();

    return json({ announcements: announcements.results });
  } },

  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/announcements$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.title?.trim()) return json({ error: 'Title required' }, 400);

    const id = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO announcements (id, team_id, title, body, pinned, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, body.title.trim(), body.body || null, body.pinned ? 1 : 0, user.userId).run();

    const settings = await env.DB.prepare('SELECT * FROM team_settings WHERE team_id = ?').bind(teamId).first();
    const announceHook = settings?.webhook_announcements || settings?.webhook_url;
    if (announceHook && settings?.on_announcement !== 0) {
      await sendDiscord(announceHook, `Announcement: ${body.title.trim()}`,
        `**${body.title.trim()}**${body.body ? '\n\n' + body.body.substring(0, 1500) : ''}\n\n— ${user.username}`, 5793266);
    }

    return json({ ok: true, id });
  } },

  // PUT/DELETE /api/teams/:id/announcements/:announcementId
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/announcements\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const [, teamId, announcementId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    await env.DB.prepare('UPDATE announcements SET title = ?, body = ?, pinned = ? WHERE id = ? AND team_id = ?')
      .bind(body.title?.trim(), body.body || null, body.pinned ? 1 : 0, announcementId, teamId).run();
    return json({ ok: true });
  } },

  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/announcements\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const [, teamId, announcementId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const announcement = await env.DB.prepare('SELECT * FROM announcements WHERE id = ? AND team_id = ?').bind(announcementId, teamId).first();
    if (!announcement) return json({ error: 'Not found' }, 404);
    if (announcement.created_by !== user.userId && member.role === 'member') return json({ error: 'No permission' }, 403);

    await env.DB.prepare('DELETE FROM announcements WHERE id = ?').bind(announcementId).run();
    return json({ ok: true });
  } },

  // POST /api/teams/:id/announcements/:id/pin — toggle pin
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/announcements\/([^/]+)\/pin$/, handler: async ({ env, user, params }) => {
    const [, teamId, announcementId] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);

    const a = await env.DB.prepare('SELECT pinned FROM announcements WHERE id = ? AND team_id = ?').bind(announcementId, teamId).first();
    if (!a) return json({ error: 'Not found' }, 404);

    await env.DB.prepare('UPDATE announcements SET pinned = ? WHERE id = ?').bind(a.pinned ? 0 : 1, announcementId).run();
    return json({ ok: true, pinned: !a.pinned });
  } },
];
