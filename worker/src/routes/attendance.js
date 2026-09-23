// Rally attendance review (protected): list claims, approve / reject / approve all, per-member
// summary, and the stored screenshot. Claims are created from Discord (routes/discord.js).

import { json, safeJson } from '../lib/http.js';
import { requireTeamMember } from '../lib/team.js';
import { approveClaims, rejectClaim, parseBosses, parseFlags } from '../lib/attendance.js';

const CLAIM_COLS = 'c.id, c.user_id, u.username, u.avatar, u.discord_id, c.bosses, c.day, c.source, c.image_key, c.note, c.flags, c.status, c.points, c.reviewed_by, c.reviewed_at, c.created_at';
const rowOut = (c) => ({ ...c, bosses: parseBosses(c.bosses), flags: parseFlags(c.flags), hasImage: !!c.image_key, image_key: undefined });

export const routes = [
  // GET /api/teams/:id/attendance?status=pending|approved|rejected|all&days=30 — members see approved; officers see all
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/attendance$/, handler: async ({ env, user, url, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    const officer = member.role !== 'member';
    const days = Math.max(1, Math.min(365, parseInt(url.searchParams.get('days')) || 30));
    let status = url.searchParams.get('status') || (officer ? 'all' : 'approved');
    if (!officer) status = 'approved';
    const since = Math.floor(Date.now() / 1000) - days * 86400;
    const rows = await env.DB.prepare(
      `SELECT ${CLAIM_COLS} FROM attendance_claims c JOIN users u ON u.id = c.user_id WHERE c.team_id = ? AND c.created_at >= ? ${status === 'all' ? '' : 'AND c.status = ?'} ORDER BY c.created_at DESC LIMIT 500`
    ).bind(...(status === 'all' ? [teamId, since] : [teamId, since, status])).all();
    const pending = officer ? (await env.DB.prepare("SELECT COUNT(*) AS n FROM attendance_claims WHERE team_id = ? AND status = 'pending'").bind(teamId).first()).n : 0;
    return json({ claims: rows.results.map(rowOut), pending, officer });
  } },

  // GET /api/teams/:id/attendance/summary?days=7 — approved rallies and points per member
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/attendance\/summary$/, handler: async ({ env, user, url, params }) => {
    const teamId = params[1];
    if (!(await requireTeamMember(env, teamId, user.userId))) return json({ error: 'Not a member' }, 403);
    const days = Math.max(1, Math.min(365, parseInt(url.searchParams.get('days')) || 7));
    const since = Math.floor(Date.now() / 1000) - days * 86400;
    const rows = await env.DB.prepare(
      "SELECT c.user_id, u.username, COUNT(*) AS rallies, SUM(c.points) AS points, MAX(c.created_at) AS last_at FROM attendance_claims c JOIN users u ON u.id = c.user_id WHERE c.team_id = ? AND c.status = 'approved' AND c.created_at >= ? GROUP BY c.user_id ORDER BY points DESC, rallies DESC, u.username"
    ).bind(teamId, since).all();
    return json({ days, members: rows.results });
  } },

  // POST /api/teams/:id/attendance/approve-all — officers+
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/attendance\/approve-all$/, handler: async ({ env, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    // flagged claims stay for a human; only clean ones are approved in bulk
    const pending = (await env.DB.prepare("SELECT * FROM attendance_claims WHERE team_id = ? AND status = 'pending'").bind(teamId).all()).results;
    const clean = pending.filter(c => parseFlags(c.flags).length === 0);
    const n = await approveClaims(env, clean, user.userId);
    return json({ ok: true, approved: n, skippedFlagged: pending.length - clean.length });
  } },

  // POST /api/teams/:id/attendance/:claimId/(approve|reject) — officers+
  { method: 'POST', pattern: /^\/api\/teams\/([^/]+)\/attendance\/([^/]+)\/(approve|reject)$/, handler: async ({ env, user, params }) => {
    const [, teamId, claimId, action] = params;
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member || member.role === 'member') return json({ error: 'Officers+ only' }, 403);
    const claim = await env.DB.prepare('SELECT * FROM attendance_claims WHERE id = ? AND team_id = ?').bind(claimId, teamId).first();
    if (!claim) return json({ error: 'Claim not found' }, 404);
    if (claim.status !== 'pending') return json({ error: `Already ${claim.status}` }, 409);
    if (action === 'approve') await approveClaims(env, [claim], user.userId);
    else await rejectClaim(env, claimId, user.userId);
    return json({ ok: true });
  } },

  // GET /api/teams/:id/attendance/:claimId/download — the stored screenshot (token may be in the query)
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/attendance\/([^/]+)\/download$/, handler: async ({ env, user, params }) => {
    const [, teamId, claimId] = params;
    if (!(await requireTeamMember(env, teamId, user.userId))) return json({ error: 'Not a member' }, 403);
    const claim = await env.DB.prepare('SELECT image_key FROM attendance_claims WHERE id = ? AND team_id = ?').bind(claimId, teamId).first();
    if (!claim?.image_key || !env.FILES) return json({ error: 'No image' }, 404);
    const obj = await env.FILES.get(claim.image_key);
    if (!obj) return json({ error: 'No image' }, 404);
    return new Response(obj.body, { headers: { 'Content-Type': obj.httpMetadata?.contentType || 'image/png', 'Cache-Control': 'private, max-age=3600' } });
  } },
];
