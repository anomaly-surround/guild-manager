// Rally attendance: claims ("I was in the rally for these bosses"), fraud flags, review, and
// points on approval. A claim comes from Discord (/here with a screenshot, or an officer's
// /rollcall) and is approved by an officer in the app — or automatically when the team's trust
// mode is on. Approval writes the team's attendance points into the existing dkp_ledger, so the
// attendance report and rewards use the same numbers as everything else.
//
// Nothing here can prove presence (the game exposes no data); the flags make faking harder and
// reviewing faster: the kill log must show the boss died that day (and not hours before the claim),
// identical screenshots are caught by hash, one claim per member per boss per day, and "approve all"
// skips anything flagged.

export const IMAGE_MAX_BYTES = 8 * 1024 * 1024;
const LATE_AFTER_MS = 3 * 3600000;       // claim more than 3 h after the kill -> 'late'
const DUP_IMAGE_WINDOW_SEC = 30 * 86400;

export function dayIn(tz, at = new Date()) {
  try { return new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(at); }
  catch { return at.toISOString().slice(0, 10); }
}

export async function attendanceSettings(env, teamId) {
  const s = await env.DB.prepare('SELECT timezone, attendance_points, attendance_auto_approve, attendance_self_checkin FROM team_settings WHERE team_id = ?').bind(teamId).first();
  return { tz: s?.timezone || 'Asia/Manila', pointsPerBoss: s?.attendance_points ?? 1, autoApprove: !!s?.attendance_auto_approve, selfCheckin: s?.attendance_self_checkin ?? 1 };
}

export function parseBosses(v) {
  try { return JSON.parse(v) || []; } catch { return []; }
}
export function parseFlags(v) {
  try { return JSON.parse(v) || []; } catch { return []; }
}

// Flags for a self check-in. bosses: [{ id, name }]; imageHash: sha256 hex or null.
export async function claimFlags(env, { teamId, userId, bosses, day, tz, imageHash, now = Date.now() }) {
  const flags = [];
  const dayStart = new Date(`${day}T00:00:00Z`).getTime() - offsetMs(tz, now);
  const dayEnd = dayStart + 86400000;
  for (const b of bosses) {
    if (!b.id) continue;
    const kill = await env.DB.prepare('SELECT killed_at FROM boss_kill_log WHERE team_id = ? AND boss_id = ? AND killed_at >= ? AND killed_at < ? ORDER BY killed_at DESC LIMIT 1')
      .bind(teamId, b.id, dayStart, dayEnd).first();
    if (!kill) flags.push({ code: 'no_kill', boss: b.name, text: `No kill of ${b.name} logged today` });
    else if (now - kill.killed_at > LATE_AFTER_MS) flags.push({ code: 'late', boss: b.name, text: `Sent ${Math.round((now - kill.killed_at) / 3600000)} h after the ${b.name} kill` });
  }
  if (imageHash) {
    const dup = await env.DB.prepare('SELECT c.id, u.username, c.day FROM attendance_claims c JOIN users u ON u.id = c.user_id WHERE c.team_id = ? AND c.image_sha256 = ? AND c.created_at >= ? LIMIT 1')
      .bind(teamId, imageHash, Math.floor(now / 1000) - DUP_IMAGE_WINDOW_SEC).first();
    if (dup) flags.push({ code: 'duplicate_image', text: `Same screenshot as ${dup.username}'s claim on ${dup.day}` });
  }
  const today = await env.DB.prepare("SELECT COUNT(*) AS n FROM attendance_claims WHERE team_id = ? AND user_id = ? AND day = ? AND status != 'rejected'").bind(teamId, userId, day).first();
  if (today.n >= 6) flags.push({ code: 'many_today', text: `${today.n} claims already today` });
  return flags;
}

// Minutes-offset of a zone at `at`, as ms (same trick as the front end's offsetMinutes).
function offsetMs(tz, at) {
  try {
    const d = new Date(Math.floor(at / 60000) * 60000);
    const p = new Intl.DateTimeFormat('en-US', { timeZone: tz, hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(d);
    const g = (t) => Number(p.find(x => x.type === t)?.value);
    return Date.UTC(g('year'), g('month') - 1, g('day'), g('hour') % 24, g('minute')) - d.getTime();
  } catch { return 0; }
}

// True when this member already claimed one of these bosses today (not rejected).
export async function alreadyClaimed(env, { teamId, userId, bosses, day }) {
  const rows = (await env.DB.prepare("SELECT bosses FROM attendance_claims WHERE team_id = ? AND user_id = ? AND day = ? AND status != 'rejected'").bind(teamId, userId, day).all()).results;
  const names = new Set(rows.flatMap(r => parseBosses(r.bosses).map(b => b.name.toLowerCase())));
  return bosses.filter(b => names.has(b.name.toLowerCase())).map(b => b.name);
}

// Create a claim. status 'pending' | 'approved'. Returns { id, points }.
export async function createClaim(env, { teamId, userId, bosses, day, source, imageKey = null, imageHash = null, note = null, flags = [], status = 'pending', pointsPerBoss = 1, reviewerId = null }) {
  const id = crypto.randomUUID();
  const points = pointsPerBoss * Math.max(1, bosses.length);
  const now = Math.floor(Date.now() / 1000);
  const stmts = [
    env.DB.prepare('INSERT INTO attendance_claims (id, team_id, user_id, bosses, day, source, image_key, image_sha256, note, flags, status, points, reviewed_by, reviewed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, teamId, userId, JSON.stringify(bosses.map(b => ({ id: b.id || null, name: b.name }))), day, source, imageKey, imageHash, note, JSON.stringify(flags), status, points,
        status === 'approved' ? (reviewerId || userId) : null, status === 'approved' ? now : null),
  ];
  if (status === 'approved') stmts.push(ledgerStmt(env, { teamId, userId, points, bosses, day, createdBy: reviewerId || userId }));
  await env.DB.batch(stmts);
  return { id, points };
}

function ledgerStmt(env, { teamId, userId, points, bosses, day, createdBy }) {
  const reason = `Rally: ${bosses.map(b => b.name).join(' + ')} (${day})`;
  return env.DB.prepare('INSERT INTO dkp_ledger (id, team_id, user_id, amount, reason, created_by) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), teamId, userId, points, reason, createdBy);
}

// Approve pending claims (rows) in one batch: status + one ledger line each. -> count approved
export async function approveClaims(env, claims, reviewerId) {
  const now = Math.floor(Date.now() / 1000);
  const stmts = [];
  for (const c of claims) {
    if (c.status !== 'pending') continue;
    stmts.push(env.DB.prepare("UPDATE attendance_claims SET status = 'approved', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'").bind(reviewerId, now, c.id));
    stmts.push(ledgerStmt(env, { teamId: c.team_id, userId: c.user_id, points: c.points, bosses: parseBosses(c.bosses), day: c.day, createdBy: reviewerId }));
  }
  if (stmts.length) await env.DB.batch(stmts);
  return stmts.length / 2;
}

export async function rejectClaim(env, claimId, reviewerId) {
  await env.DB.prepare("UPDATE attendance_claims SET status = 'rejected', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'")
    .bind(reviewerId, Math.floor(Date.now() / 1000), claimId).run();
}

// Fetch a Discord attachment (links expire) -> { buf, hash } or null. Stored to R2 after the claim row exists.
export async function fetchImage(url, size) {
  if (!url || (size && size > IMAGE_MAX_BYTES)) return null;
  try {
    const r = await fetch(url);
    if (!r.ok) return null;
    const buf = await r.arrayBuffer();
    if (buf.byteLength > IMAGE_MAX_BYTES) return null;
    const digest = await crypto.subtle.digest('SHA-256', buf);
    const hash = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    return { buf, hash };
  } catch (e) { console.error('attendance image fetch failed:', e); return null; }
}

export async function storeImage(env, { teamId, claimId, buf, contentType }) {
  if (!env.FILES || !buf) return null;
  try {
    const key = `attendance/${teamId}/${claimId}`;
    await env.FILES.put(key, buf, { httpMetadata: { contentType: contentType || 'image/png' } });
    await env.DB.prepare('UPDATE attendance_claims SET image_key = ? WHERE id = ?').bind(key, claimId).run();
    return key;
  } catch (e) { console.error('attendance image store failed:', e); return null; }
}
