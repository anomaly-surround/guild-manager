// Built-in boss lists per game (free for every team: the cold-start fix). One file per game.
// Boss entries use the same shape as a POST /bosses body: { name, type, intervalMs | fixedTime |
// weeklyDay+weeklyTime | biweeklyDays | twiceDailyTimes, location?, alertMinutes?, windowMs? }.

import { LORD_NINE } from './lordnine.js';

export const PRESETS = [LORD_NINE];

export function findPreset(id) {
  return PRESETS.find(p => p.id === id) || null;
}
