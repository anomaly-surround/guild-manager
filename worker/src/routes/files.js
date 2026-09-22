// File vault (R2) (protected routes)

import { json, corsHeaders, sanitizeStr } from '../lib/http.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';

export const routes = [
  // GET /api/teams/:id/files — list files
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/files$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    const files = await env.DB.prepare(`
      SELECT tf.*, u.username as uploaded_by_name FROM team_files tf
      LEFT JOIN users u ON u.id = tf.uploaded_by
      WHERE tf.team_id = ? ORDER BY tf.created_at DESC
    `).bind(teamId).all();

    // Calculate total storage used
    const total = await env.DB.prepare('SELECT COALESCE(SUM(file_size), 0) as total FROM team_files WHERE team_id = ?').bind(teamId).first();

    return json({ files: files.results, totalBytes: total.total });
  } },

  // POST /api/teams/:id/files — upload file
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/files$/, handler: async ({ request, env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    if (!env.FILES) return json({ error: 'File storage not configured' }, 500);

    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      const file = formData.get('file');
      if (!file) return json({ error: 'No file provided' }, 400);

      const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
      if (file.size > MAX_FILE_SIZE) return json({ error: 'File too large (max 5MB)' }, 400);

      // Check team storage limit
      const premium = await isPremiumTeam(env, teamId);
      const storageLimit = premium ? 500 * 1024 * 1024 : 100 * 1024 * 1024; // 500MB premium, 100MB free
      const current = await env.DB.prepare('SELECT COALESCE(SUM(file_size), 0) as total FROM team_files WHERE team_id = ?').bind(teamId).first();
      if (current.total + file.size > storageLimit) return json({ error: `Storage limit reached (${premium ? '500MB' : '100MB'})` }, 400);

      const fileId = crypto.randomUUID();
      const r2Key = `teams/${teamId}/${fileId}/${file.name}`;

      await env.FILES.put(r2Key, file.stream(), {
        httpMetadata: { contentType: file.type || 'application/octet-stream' },
      });

      await env.DB.prepare('INSERT INTO team_files (id, team_id, file_name, file_size, content_type, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)')
        .bind(fileId, teamId, file.name.slice(0, 200), file.size, file.type || 'application/octet-stream', user.userId).run();

      return json({ ok: true, id: fileId });
    }

    return json({ error: 'Use multipart/form-data' }, 400);
  } },

  // GET /api/teams/:id/files/:fileId/download — download file
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/files\/([^/]+)\/download$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const fileId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);

    if (!env.FILES) return json({ error: 'File storage not configured' }, 500);

    const fileMeta = await env.DB.prepare('SELECT * FROM team_files WHERE id = ? AND team_id = ?').bind(fileId, teamId).first();
    if (!fileMeta) return json({ error: 'File not found' }, 404);

    const r2Key = `teams/${teamId}/${fileId}/${fileMeta.file_name}`;
    const object = await env.FILES.get(r2Key);
    if (!object) return json({ error: 'File not found in storage' }, 404);

    return new Response(object.body, {
      headers: {
        'Content-Type': fileMeta.content_type,
        'Content-Disposition': `attachment; filename="${sanitizeStr(fileMeta.file_name).replace(/[^a-zA-Z0-9._-]/g, '_')}"`,
        ...corsHeaders(),
      },
    });
  } },

  // DELETE /api/teams/:id/files/:fileId
  { method: 'DELETE', pattern: /^\/api\/teams\/([^/]+)\/files\/([^/]+)$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const fileId = params[2];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || (member.role !== 'leader' && member.role !== 'officer')) return json({ error: 'Leaders/officers only' }, 403);

    if (!env.FILES) return json({ error: 'File storage not configured' }, 500);

    const fileMeta = await env.DB.prepare('SELECT * FROM team_files WHERE id = ? AND team_id = ?').bind(fileId, teamId).first();
    if (fileMeta) {
      const r2Key = `teams/${teamId}/${fileId}/${fileMeta.file_name}`;
      await env.FILES.delete(r2Key);
      await env.DB.prepare('DELETE FROM team_files WHERE id = ?').bind(fileId).run();
    }

    return json({ ok: true });
  } },
];
