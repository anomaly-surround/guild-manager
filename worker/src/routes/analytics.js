// Analytics feeds + CSV export (protected routes)

import { json, corsHeaders } from '../lib/http.js';
import { requireTeamMember, isPremiumTeam } from '../lib/team.js';

export const routes = [
  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/analytics$/, handler: async ({ env, url, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const type = url.searchParams.get('type') || 'activity';

    if (type === 'activity') {
      const activity = await env.DB.prepare(`
        SELECT u.username, ma.last_seen FROM member_activity ma
        JOIN users u ON u.id = ma.user_id WHERE ma.team_id = ?
      `).bind(teamId).all();
      return json({ data: activity.results });
    } else if (type === 'wars') {
      const wars = await env.DB.prepare(`
        SELECT result, war_date, opponent FROM war_log WHERE team_id = ? ORDER BY war_date ASC
      `).bind(teamId).all();
      return json({ data: wars.results });
    } else if (type === 'dkp') {
      const dkp = await env.DB.prepare(`
        SELECT dl.user_id, u.username, dl.amount, dl.reason, dl.created_at
        FROM dkp_ledger dl JOIN users u ON u.id = dl.user_id
        WHERE dl.team_id = ? ORDER BY dl.created_at ASC
      `).bind(teamId).all();
      return json({ data: dkp.results });
    } else if (type === 'attendance') {
      const att = await env.DB.prepare(`
        SELECT u.username, COUNT(CASE WHEN ea.attended = 1 THEN 1 END) as attended,
          COUNT(e.id) as total
        FROM team_members tm
        JOIN users u ON u.id = tm.user_id
        LEFT JOIN events e ON e.team_id = tm.team_id
        LEFT JOIN event_attendance ea ON ea.event_id = e.id AND ea.user_id = tm.user_id
        WHERE tm.team_id = ? GROUP BY u.id ORDER BY attended DESC
      `).bind(teamId).all();
      return json({ data: att.results });
    }
    return json({ data: [] });
  } },

  { method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/export$/, handler: async ({ env, url, user, params }) => {
    const teamId = params[1];
    const member = await requireTeamMember(env, teamId, user.userId);
    if (!member) return json({ error: 'Not a member' }, 403);
    if (!(await isPremiumTeam(env, teamId))) return json({ error: 'Premium required', premiumRequired: true }, 403);

    const type = url.searchParams.get('type') || 'members';
    let csv = '';

    if (type === 'members') {
      csv = 'Username,Role,Joined\n';
      const rows = await env.DB.prepare('SELECT u.username, tm.role, tm.joined_at FROM team_members tm JOIN users u ON u.id = tm.user_id WHERE tm.team_id = ?').bind(teamId).all();
      for (const r of rows.results) csv += `${r.username},${r.role},${new Date(r.joined_at * 1000).toISOString()}\n`;
    } else if (type === 'dkp') {
      csv = 'Username,Amount,Reason,Date\n';
      const rows = await env.DB.prepare('SELECT u.username, dl.amount, dl.reason, dl.created_at FROM dkp_ledger dl JOIN users u ON u.id = dl.user_id WHERE dl.team_id = ? ORDER BY dl.created_at DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.username}",${r.amount},"${r.reason}",${new Date(r.created_at * 1000).toISOString()}\n`;
    } else if (type === 'wars') {
      csv = 'Opponent,Result,Score,Date\n';
      const rows = await env.DB.prepare('SELECT * FROM war_log WHERE team_id = ? ORDER BY war_date DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.opponent}",${r.result},${r.score_us ?? ''}-${r.score_them ?? ''},${new Date(r.war_date * 1000).toISOString()}\n`;
    } else if (type === 'loot') {
      csv = 'Item,Boss,Recipient,DKP Cost,Date\n';
      const rows = await env.DB.prepare('SELECT bl.*, u.username FROM boss_loot bl JOIN users u ON u.id = bl.recipient_id WHERE bl.team_id = ? ORDER BY bl.created_at DESC').bind(teamId).all();
      for (const r of rows.results) csv += `"${r.item_name}","${r.boss_name}","${r.username}",${r.dkp_cost},${new Date(r.created_at * 1000).toISOString()}\n`;
    }

    return new Response(csv, {
      headers: { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="${type}-export.csv"`, ...corsHeaders() },
    });
  } },
];
