# Front-end layout

`index.html` is markup only. Styles live in `css/app.css`; behaviour is split into one classic
script per feature under `js/`, loaded in order at the end of `<body>`.

Classic scripts (not ES modules) on purpose: the tab templates use inline `onclick="fn()"` handlers
and the features share top-level state (`currentTeamId`, `teamData`, ...). Classic scripts share one
global scope exactly like the original single inline script did, so this split is a pure move.
Migrating a feature to a module with explicit imports and state is part of the overhaul, tab by tab.

Load order matters only for code that runs at load time:

| file | runs at load |
|---|---|
| `theme-help.js` | applies the saved theme |
| `core.js` | API base, Paddle init, session state, `guard()` |
| `util.js` | generic helpers |
| `api.js` | `api()` + TTL cache (must precede any caller that runs at load) |
| `notifications.js` | requests notification permission |
| `auth.js` | reads `?token=` from an OAuth redirect into localStorage |
| feature files | function definitions only |
| `timers.js` | starts the background `setInterval` loops |
| `main.js` | `init()` — always last |

One file per tab: `bosses`, `members`, `settings`, `dashboard`, `chat`, `analytics`, `announcements`,
`wars`, `matches`, `loot`, `dkp`, `availability`, `events`, `polls`, `rosters`, `performance`,
`recruitment`, `files`. Shared screens: `auth`, `billing`, `teams`, `team-view`.

Local test harness: serve the folder on one origin and proxy `/api` + `/auth` to `wrangler dev`
(the worker only allows the GitHub Pages origin, so a plain file server cannot reach it).
