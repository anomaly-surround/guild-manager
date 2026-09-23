# Guild Manager — Worker

Cloudflare Worker backend for the Guild Manager SPA (`../index.html`, served by GitHub Pages).
Live at `https://guild-manager.xpropics.workers.dev`.

## Deploy

```
cd worker; npx wrangler deploy
```

Bindings (D1 `DB`, R2 `FILES`) and the every-minute cron live in `wrangler.toml`.
Secrets (`DISCORD_*`, `GOOGLE_*`, `JWT_SECRET`) are set in the Cloudflare dashboard and survive
deploys. Gumroad billing needs no secret: the four `GUMROAD_*` values are plain vars in `wrangler.toml`. Roll back with `npx wrangler rollback`.

Dropping the tables of cut features from production is a manual step: see `DROP_TABLES.md`.

## Run locally

```
cd worker; npx wrangler dev --local
```

Uses a fresh local D1 + R2. Put local-only secrets in `worker/.dev.vars` (gitignored), e.g.
`JWT_SECRET = "localtest"`.

## Layout — one responsibility per file

```
src/
  index.js            entry: fetch -> router, scheduled -> cron; top-level error wrapper
  router.js           pipeline: OPTIONS, schema init, auth rate-limit, public routes,
                      auth guard, protected routes, 404
  db/schema.js        CREATE TABLE IF NOT EXISTS + idempotent migrations, once per isolate
  cron/scheduled.js   every-minute tick: boss timers, event notices, recurring events,
                      DKP decay, auction close, auto-delete, join-request cleanup
  lib/
    http.js           json(), corsHeaders(), safeJson(), sanitizeStr()
    auth.js           createToken(), verifyToken(), getUser()
    ratelimit.js      per-isolate in-memory rate limiter
    ids.js            generateInviteCode()
    spawn.js          boss spawn-time math
    discord.js        webhook validation + embed sender
    gumroad.js        checkout link, license verify, grant/revoke premium, daily recheck
    team.js           requireTeamMember(env, teamId, userId), isPremiumTeam(env, teamId)
    rotation.js       lootModeFor(), ensurePositions(), moveMember() — loot rotation math
  routes/             one module per resource; each exports `routes = [{ method, pattern, handler }]`
    auth.js           /auth/*                     (public)
    billing.js        /gumroad/ping, activate-license, start-trial, checkout   (public)
    public.js         /public/timers/:token       (public, read-only timer page)
    teams.js          teams CRUD, member game role, roles, kick/leave/transfer
    invites.js        invite codes, join requests
    bosses.js         bosses (+window/location), kill, edit, templates, game presets, history
    settings.js       settings (incl. modules, loot mode, RSVP roles, public timers, points name), webhook test
    events.js         events, RSVP by role, caps, lineup, attendance, templates, report, iCal
    members.js        officer notes, heartbeat, availability
    loot.js  dkp.js   Loot & Points (optional module): loot log, wishlist, points, auctions
    rotation.js       loot rotation order, officer moves, leader reset
  lib/limits.js       plan limits (Free / Premium)
  lib/boss-create.js  next spawn per schedule type + the INSERT statement (create, template import, presets)
  presets/            built-in boss lists per game (lordnine.js, ...) served by GET /api/presets
```

## Adding a route

Append `{ method: 'GET', pattern: /^\/api\/teams\/([^/]+)\/thing$/, handler: async ({ env, user, params }) => { ... } }`
to the matching `routes/*.js`. `params` is the RegExp match array (`params[1]` = teamId).
Handlers under `routes/` other than `auth.js` and `billing.js` always receive a logged-in `user`;
the router already returned 401 otherwise. Use `requireTeamMember(env, teamId, user.userId)` for
membership and role checks, exactly like the neighbouring handlers.

Routes are matched in array order. `method: '*'` matches any verb.

## History

Split from a single 3,600-line `worker.js` on 2026-09-22 by a line-range generator, no behaviour
change. Verified by replaying a 109-step session against old and new workers side by side and
diffing the normalised transcripts (identical apart from a local R2-binding config difference).
