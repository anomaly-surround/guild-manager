// Boss spawn-time math (all in the team's timezone)

export function getNextFixedSpawn(timeStr, tz) {
  const [h, m] = timeStr.split(':').map(Number);
  const now = new Date();
  const local = new Date(now.toLocaleString('en-US', { timeZone: tz }));
  const spawn = new Date(local);
  spawn.setHours(h, m, 0, 0);
  if (spawn <= local) spawn.setDate(spawn.getDate() + 1);
  const offset = now.getTime() - local.getTime();
  return spawn.getTime() + offset;
}

export function getNextWeeklySpawn(targetDay, timeStr, tz) {
  const [h, m] = timeStr.split(':').map(Number);
  const now = new Date();
  const local = new Date(now.toLocaleString('en-US', { timeZone: tz }));
  const spawn = new Date(local);
  spawn.setHours(h, m, 0, 0);
  let daysUntil = targetDay - local.getDay();
  if (daysUntil < 0) daysUntil += 7;
  if (daysUntil === 0 && spawn <= local) daysUntil = 7;
  spawn.setDate(spawn.getDate() + daysUntil);
  const offset = now.getTime() - local.getTime();
  return spawn.getTime() + offset;
}

export function getNextBiweeklySpawn(days, tz) {
  const parsed = typeof days === 'string' ? JSON.parse(days) : days;
  return Math.min(...parsed.map(d => getNextWeeklySpawn(d.day, d.time, tz)));
}

export function getNextTwiceDailySpawn(times, tz) {
  if (!times) return Date.now() + 3600000;
  const parsed = typeof times === 'string' ? JSON.parse(times) : times;
  if (!Array.isArray(parsed) || parsed.length === 0) return Date.now() + 3600000;
  const spawns = parsed.map(t => getNextFixedSpawn(t, tz));
  return Math.min(...spawns);
}

export function calcNextSpawn(boss, fromTime, tz) {
  if (boss.type === 'interval') return fromTime + boss.interval_ms;
  if (boss.type === 'fixed') return getNextFixedSpawn(boss.fixed_time, tz);
  if (boss.type === 'weekly') return getNextWeeklySpawn(boss.weekly_day, boss.weekly_time, tz);
  if (boss.type === 'biweekly') return getNextBiweeklySpawn(boss.biweekly_days, tz);
  if (boss.type === 'twicedaily') return getNextTwiceDailySpawn(boss.biweekly_days, tz);
  return fromTime + 3600000;
}
