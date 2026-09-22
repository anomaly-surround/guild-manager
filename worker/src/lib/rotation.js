// Loot mode + loot-rotation position math (shared by routes/loot.js and routes/rotation.js)
//
// team_members.loot_pos is the member's place in the rotation. NULL means "not placed yet",
// which sorts LAST (newcomers start at the bottom). Positions are only materialised when a
// move needs them, so a team that never touches the rotation just runs in join order.

export async function lootModeFor(env, teamId) {
  const row = await env.DB.prepare('SELECT loot_mode FROM team_settings WHERE team_id = ?').bind(teamId).first();
  if (row?.loot_mode === 'dkp' || row?.loot_mode === 'rotation') return row.loot_mode;
  // Unset: teams that already run a points ledger stay on DKP, everyone else gets rotation.
  const used = await env.DB.prepare('SELECT COUNT(*) AS n FROM dkp_ledger WHERE team_id = ?').bind(teamId).first();
  return (used?.n || 0) > 0 ? 'dkp' : 'rotation';
}

// rowid breaks same-second joined_at ties so the fallback really is join order.
export const ROTATION_ORDER_SQL = 'ORDER BY (tm.loot_pos IS NULL), tm.loot_pos, tm.joined_at, tm.rowid';

async function orderedRows(env, teamId) {
  const r = await env.DB.prepare(
    `SELECT tm.user_id, tm.loot_pos FROM team_members tm WHERE tm.team_id = ? ${ROTATION_ORDER_SQL}`
  ).bind(teamId).all();
  return r.results;
}

// Give every member a concrete position (1..n) in the current effective order, if any is missing.
export async function ensurePositions(env, teamId) {
  const rows = await orderedRows(env, teamId);
  if (rows.length && rows.every(r => r.loot_pos !== null)) return rows;
  if (rows.length) {
    await env.DB.batch(rows.map((r, i) =>
      env.DB.prepare('UPDATE team_members SET loot_pos = ? WHERE team_id = ? AND user_id = ?').bind(i + 1, teamId, r.user_id)));
  }
  return rows.map((r, i) => ({ ...r, loot_pos: i + 1 }));
}

// to: 'top' | 'bottom' | 'up' | 'down'. Returns false when the user is not a member.
export async function moveMember(env, teamId, userId, to) {
  const rows = await ensurePositions(env, teamId);
  const i = rows.findIndex(r => r.user_id === userId);
  if (i < 0) return false;
  const set = (uid, pos) => env.DB.prepare('UPDATE team_members SET loot_pos = ? WHERE team_id = ? AND user_id = ?').bind(pos, teamId, uid);
  const first = rows[0].loot_pos, last = rows[rows.length - 1].loot_pos;
  if (to === 'bottom') await set(userId, last + 1).run();
  else if (to === 'top') await set(userId, first - 1).run();
  else if (to === 'up' && i > 0) await env.DB.batch([set(userId, rows[i - 1].loot_pos), set(rows[i - 1].user_id, rows[i].loot_pos)]);
  else if (to === 'down' && i < rows.length - 1) await env.DB.batch([set(userId, rows[i + 1].loot_pos), set(rows[i + 1].user_id, rows[i].loot_pos)]);
  return true;
}
