// Discord slash commands (public route, signed by Discord): /link, /unlink, /next, /killed.
//
// One Discord server ↔ one team (team_settings.discord_guild_id). /next is open to anyone in the
// linked server (the discovery surface); /killed needs the Discord account to be a member of the
// team in Guild Manager; /link and /unlink need officer+. Discord expects an answer within 3 s and
// this worker's database is far from Discord's servers, so commands are acknowledged with a
// deferred response and finished in ctx.waitUntil (editOriginal). Autocomplete has no deferral,
// so it does one query and answers directly.

import { json } from '../lib/http.js';
import { killBoss } from '../lib/boss-kill.js';
import {
  InteractionType, verifyDiscordRequest, pong, message, deferred, choices, editOriginal,
  optionValue, focusedOption, invoker, nextSpawnsText, fmtDuration, clockIn,
} from '../lib/discord-interactions.js';

const APP_URL = 'https://anomaly-surround.github.io/guild-manager/';

async function linkedTeam(env, guildId) {
  if (!guildId) return null;
  return env.DB.prepare('SELECT t.id, t.name, ts.timezone, ts.public_token FROM team_settings ts JOIN teams t ON t.id = ts.team_id WHERE ts.discord_guild_id = ?')
    .bind(guildId).first();
}
async function membership(env, teamId, discordUserId) {
  return env.DB.prepare('SELECT m.user_id, m.role FROM team_members m JOIN users u ON u.id = m.user_id WHERE m.team_id = ? AND u.discord_id = ?')
    .bind(teamId, discordUserId).first();
}
const footer = (team) => `\n-# Team time (${team.timezone || 'Asia/Manila'}) · ${team.public_token ? `[Timer page](${APP_URL}timers.html?t=${team.public_token}) · ` : ''}[Guild Manager](${APP_URL})`;

// ---- commands (each returns the text to show)

async function cmdLink(env, interaction) {
  const code = String(optionValue(interaction, 'code') || '').trim();
  const who = invoker(interaction);
  if (!interaction.guild_id) return 'Run this inside the Discord server you want to link.';
  const team = await env.DB.prepare('SELECT id, name FROM teams WHERE invite_code = ?').bind(code).first();
  if (!team) return 'No team has that invite code. It is in the team bar in Guild Manager.';
  const m = await membership(env, team.id, who.id);
  if (!m) return `Your Discord account is not a member of **${team.name}** in Guild Manager. Sign in there with Discord first.`;
  if (m.role === 'member') return 'Only the leader or an officer can link a server.';
  await env.DB.batch([
    env.DB.prepare('UPDATE team_settings SET discord_guild_id = NULL WHERE discord_guild_id = ?').bind(interaction.guild_id),
    // a team has no settings row until something is saved, so upsert
    env.DB.prepare('INSERT INTO team_settings (team_id, discord_guild_id) VALUES (?, ?) ON CONFLICT(team_id) DO UPDATE SET discord_guild_id = excluded.discord_guild_id').bind(team.id, interaction.guild_id),
  ]);
  return `Linked this server to **${team.name}**. Everyone here can use \`/next\`; team members can log kills with \`/killed\`.`;
}

async function cmdUnlink(env, interaction) {
  const team = await linkedTeam(env, interaction.guild_id);
  if (!team) return 'This server is not linked to a team.';
  const m = await membership(env, team.id, invoker(interaction).id);
  if (!m || m.role === 'member') return 'Only the leader or an officer can unlink.';
  await env.DB.prepare('UPDATE team_settings SET discord_guild_id = NULL WHERE team_id = ?').bind(team.id).run();
  return `Unlinked **${team.name}** from this server.`;
}

async function cmdNext(env, interaction) {
  const team = await linkedTeam(env, interaction.guild_id);
  if (!team) return 'This server is not linked to a team yet. A leader or officer runs `/link <invite code>`.';
  const count = Math.max(1, Math.min(25, Number(optionValue(interaction, 'count')) || 10));
  const bosses = await env.DB.prepare('SELECT * FROM bosses WHERE team_id = ?').bind(team.id).all();
  return `**${team.name}** — next spawns\n${nextSpawnsText(bosses.results, team.timezone || 'Asia/Manila', Date.now(), count)}${footer(team)}`;
}

async function cmdKilled(env, interaction) {
  const team = await linkedTeam(env, interaction.guild_id);
  if (!team) return 'This server is not linked to a team yet. A leader or officer runs `/link <invite code>`.';
  const who = invoker(interaction);
  const m = await membership(env, team.id, who.id);
  if (!m) return `Only members of **${team.name}** in Guild Manager can log kills. Join the team there with your Discord account.`;
  const wanted = String(optionValue(interaction, 'boss') || '').trim();
  const minutesAgo = Math.max(0, Math.min(1440, Number(optionValue(interaction, 'minutes_ago')) || 0));
  const bosses = (await env.DB.prepare('SELECT * FROM bosses WHERE team_id = ?').bind(team.id).all()).results;
  let boss = bosses.find(b => b.id === wanted) || bosses.find(b => b.name.toLowerCase() === wanted.toLowerCase());
  if (!boss) {
    const hits = bosses.filter(b => b.name.toLowerCase().includes(wanted.toLowerCase()));
    if (hits.length === 1) boss = hits[0];
    else if (hits.length > 1) return `Which one? ${hits.slice(0, 8).map(b => `**${b.name}**`).join(', ')}`;
    else return `No boss called "${wanted}" on this team.`;
  }
  const deathTime = Date.now() - minutesAgo * 60000;
  const { nextSpawn } = await killBoss(env, { teamId: team.id, boss, deathTime, userId: m.user_id, tz: team.timezone });
  const when = minutesAgo ? ` (${minutesAgo} min ago)` : '';
  return `☠️ **${boss.name}** killed by ${who.name}${when}. Next spawn in ${fmtDuration(nextSpawn - Date.now())} (${clockIn(nextSpawn, team.timezone || 'Asia/Manila')}).${footer(team)}`;
}

const COMMANDS = { link: cmdLink, unlink: cmdUnlink, next: cmdNext, killed: cmdKilled };
const EPHEMERAL_COMMANDS = new Set(['link', 'unlink']);

export const routes = [
  { method: 'POST', pattern: '/discord/interactions', handler: async ({ request, env, ctx }) => {
    const raw = await request.text();
    if (!(await verifyDiscordRequest(request, raw, env.DISCORD_PUBLIC_KEY))) return json({ error: 'bad signature' }, 401);
    let interaction;
    try { interaction = JSON.parse(raw); } catch { return json({ error: 'bad body' }, 400); }

    if (interaction.type === InteractionType.PING) return pong();

    if (interaction.type === InteractionType.AUTOCOMPLETE) {
      const team = await linkedTeam(env, interaction.guild_id);
      if (!team) return choices([]);
      const q = String(focusedOption(interaction)?.value || '').toLowerCase();
      const bosses = (await env.DB.prepare('SELECT id, name FROM bosses WHERE team_id = ? ORDER BY name').bind(team.id).all()).results;
      return choices(bosses.filter(b => !q || b.name.toLowerCase().includes(q)).map(b => ({ name: b.name.slice(0, 100), value: b.id })));
    }

    if (interaction.type === InteractionType.COMMAND) {
      const name = interaction.data?.name;
      const fn = COMMANDS[name];
      if (!fn) return message(`Unknown command /${name}`, true);
      const ephemeral = EPHEMERAL_COMMANDS.has(name);
      const work = fn(env, interaction)
        .catch(e => { console.error(`discord /${name} failed:`, e); return 'Something went wrong on our side. Try again in a minute.'; })
        .then(text => editOriginal(env, interaction.token, text));
      if (ctx?.waitUntil) { ctx.waitUntil(work); return deferred(ephemeral); }
      await work; return deferred(ephemeral);   // local harness without ctx
    }

    return json({ error: 'unsupported interaction' }, 400);
  } },
];
