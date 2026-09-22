// Recruitment board + applications (protected routes)

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/recruitment
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/recruitment$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const posts = await env.DB.prepare(`
      SELECT rp.*, u.username as created_by_name FROM recruitment_posts rp
      LEFT JOIN users u ON u.id = rp.created_by
      WHERE rp.team_id = ? ORDER BY rp.created_at DESC
    `).bind(teamId).all();

    const canManage = member.role === 'leader' || member.role === 'officer';
    for (const post of posts.results) {
      if (canManage) {
        const apps = await env.DB.prepare(`
          SELECT ra.*, u.username as applicant_name, u.avatar as applicant_avatar FROM recruitment_applications ra
          LEFT JOIN users u ON u.id = ra.user_id
          WHERE ra.post_id = ? ORDER BY ra.created_at DESC
        `).bind(post.id).all();
        post.applications = apps.results;
      } else {
        const count = await env.DB.prepare('SELECT COUNT(*) as count FROM recruitment_applications WHERE post_id = ?').bind(post.id).first();
        post.applicationCount = count.count;
        // Check if current user applied
        const myApp = await env.DB.prepare('SELECT status FROM recruitment_applications WHERE post_id = ? AND user_id = ?').bind(post.id, user.userId).first();
        post.myApplication = myApp || null;
      }
    }

    return json({ posts: posts.results });
  } },

  // POST /api/teams/:id/recruitment — create post
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/recruitment$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (!body.title) return json({ error: 'Title required' }, 400);

    const postId = crypto.randomUUID();
    await env.DB.prepare('INSERT INTO recruitment_posts (id, team_id, title, description, role_needed, created_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(postId, teamId, body.title.slice(0, 100), (body.description || '').slice(0, 500), (body.roleNeeded || '').slice(0, 50), user.userId).run();

    return json({ ok: true, id: postId });
  } },

  // PUT /api/teams/:id/recruitment/:postId — update status (open/closed)
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const postId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (body.status) {
      await env.DB.prepare('UPDATE recruitment_posts SET status = ? WHERE id = ? AND team_id = ?').bind(body.status, postId, teamId).run();
    }
    return json({ ok: true });
  } },

  // DELETE /api/teams/:id/recruitment/:postId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const postId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    await env.DB.prepare('DELETE FROM recruitment_applications WHERE post_id = ?').bind(postId).run();
    await env.DB.prepare('DELETE FROM recruitment_posts WHERE id = ? AND team_id = ?').bind(postId, teamId).run();
    return json({ ok: true });
  } },

  // POST /api/teams/:id/recruitment/:postId/apply — apply to a post
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)\/apply$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const postId = params[2];

    const post = await env.DB.prepare('SELECT * FROM recruitment_posts WHERE id = ? AND team_id = ?').bind(postId, teamId).first();
    if (!post) return json({ error: 'Post not found' }, 404);
    if (post.status === 'closed') return json({ error: 'This position is closed' }, 400);

    // Check if already applied
    const existing = await env.DB.prepare('SELECT id FROM recruitment_applications WHERE post_id = ? AND user_id = ?').bind(postId, user.userId).first();
    if (existing) return json({ error: 'Already applied' }, 400);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    await env.DB.prepare('INSERT INTO recruitment_applications (id, post_id, user_id, message) VALUES (?, ?, ?, ?)')
      .bind(crypto.randomUUID(), postId, user.userId, (body.message || '').slice(0, 500)).run();

    return json({ ok: true });
  } },

  // PUT /api/teams/:id/recruitment/:postId/applications/:appId — accept/reject
  { method: 'PUT', pattern: /^\/api\/teams\/([^/]+)\/recruitment\/([^/]+)\/applications\/([^/]+)$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const appId = params[3];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    const body = await safeJson(request);
    if (!body) return json({ error: "Invalid request body" }, 400);
    if (body.status === 'accepted' || body.status === 'rejected') {
      await env.DB.prepare('UPDATE recruitment_applications SET status = ?, reviewed_by = ? WHERE id = ?')
        .bind(body.status, user.userId, appId).run();
    }
    return json({ ok: true });
  } },
];
