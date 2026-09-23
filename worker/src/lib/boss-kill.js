// Logging a boss kill: reset the timer from the death time and record it. Shared by the
// POST /bosses/:id/kill route and the Discord /killed command.

import { calcNextSpawn } from './spawn.js';

// boss: full bosses row. -> { nextSpawn }
export async function killBoss(env, { teamId, boss, deathTime, userId, tz }) {
  const nextSpawn = calcNextSpawn(boss, deathTime, tz || 'Asia/Manila');
  await env.DB.batch([
    env.DB.prepare('UPDATE bosses SET status = ?, spawned_at = NULL, auto_reset_at = NULL, last_death = ?, next_spawn = ?, warned = 0, spawn_notified = 0 WHERE id = ?')
      .bind('waiting', deathTime, nextSpawn, boss.id),
    env.DB.prepare('INSERT INTO boss_kill_log (id, team_id, boss_id, boss_name, killed_at, killed_by) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), teamId, boss.id, boss.name, deathTime, userId || null),
  ]);
  return { nextSpawn };
}
