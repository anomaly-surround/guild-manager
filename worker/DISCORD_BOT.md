# Discord slash commands — setup and how it works

Built 2026-09-23 (M13). Same Discord application as the "Continue with Discord" login
(app id `1488742496660881528`, in `wrangler.toml` as `DISCORD_APP_ID`; public key `DISCORD_PUBLIC_KEY`).
The bot token is the secret `DISCORD_BOT_TOKEN` (`npx wrangler secret put DISCORD_BOT_TOKEN`); the
worker itself never needs it — only `scripts/register-commands.mjs` does.

## Commands

| Command | Who | Does |
|---|---|---|
| `/link <code>` | leader/officer of the team, signed in to Guild Manager with Discord | ties this Discord server to the team with that invite code (a server belongs to one team; a team may link many servers — `discord_guilds`) |
| `/unlink` | leader/officer | removes the tie (also possible from Settings → Discord slash commands) |
| `/next [count]` | **anyone** in the linked server | next spawns, up-now first, team time, with a link to the timer page / app |
| `/killed <boss> [minutes_ago]` | team members only | logs the kill and restarts the timer; boss name autocompletes; ambiguous names ask "which one?" |

`/next` is deliberately open: it is the discovery surface (every reply carries the Guild Manager
link). `/killed` is not, because a stranger in a public server could reset a guild's timers.

## One-time setup (portal + terminal)

1. **Interactions Endpoint URL** — Developer Portal → the app → General Information →
   `https://guild-manager.xpropics.workers.dev/discord/interactions` → Save. Discord sends a signed
   PING; the worker must answer PONG or the save is refused (that is the signature check working).
2. **Register the commands** (from the worker folder, token in the environment, never in a file):
   ```
   $env:DISCORD_BOT_TOKEN='<token>'; node scripts/register-commands.mjs
   ```
   Global registration can take up to an hour to show in clients. For instant testing on one server:
   `node scripts/register-commands.mjs <server id>` (Developer Mode → right-click the server → Copy ID).
3. **Redirect URI** (one-time, so the one-click link works) — Developer Portal → OAuth2 → Redirects → add
   `https://guild-manager.xpropics.workers.dev/discord/added` → Save.

## What a guild leader does (every guild)

Settings → Discord slash commands → **Add to Discord**. Discord asks which server; on Authorize it
sends the leader to `/discord/added?guild_id=…&state=…` where `state` is our signed token naming the
team and the user (issued by `GET /api/teams/:id/discord-link`, officer+). The worker links the server
and redirects back to the app with `?discord=linked`. Scopes: `applications.commands bot` with
permissions 0 — the `bot` scope is what makes Discord include `guild_id` in the redirect; the bot
user reads nothing and has no permissions. Fallback: `/link <invite code>` in the server.

## How a command is handled (`routes/discord.js`, `lib/discord-interactions.js`)

- Discord signs `timestamp + body` with the app's Ed25519 key. `verifyDiscordRequest` checks it with
  WebCrypto; anything unsigned or mis-signed gets 401 (tested).
- Discord requires an answer within 3 s and this worker's D1 sits in Hong Kong, far from Discord's
  servers. So commands are acknowledged with a **deferred** response immediately and completed in
  `ctx.waitUntil`, which then PATCHes the placeholder via the interaction token (`editOriginal`).
  Autocomplete cannot be deferred: it does one query and answers directly.
- `/link` and `/unlink` replies are ephemeral (only the invoker sees them).
- Membership = `users.discord_id` (from Discord login) joined to `team_members`. Google-only accounts
  cannot use `/killed` until they sign in with Discord once (Discord login on the same account is not
  supported yet — separate accounts).

## Local test

`.dev.vars` holds a TEST public key (`DISCORD_PUBLIC_KEY`) and `DISCORD_API = http://127.0.0.1:8797`;
the scratchpad's `m13_discord_test.mjs` signs requests with the matching private key and runs a mock
Discord API that records the follow-up edits. 24 checks. Production uses the real key from `wrangler.toml`.
