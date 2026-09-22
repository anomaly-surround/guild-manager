# Guild Manager overhaul — plan of record

Decided 2026-09-22. Direction: **fewer, stronger features**, built around **boss timers and events**,
useful across MMOs without being game-specific, with a **visual redesign** on top. This file is the
lock; reopen a decision here only with a new reason, not a new mood.

## Thesis

An MMO guild has three recurring coordination problems that Discord alone does badly:

1. **When does the boss spawn?** Shared timers with kill logging, alerts, and a Discord ping.
2. **When is the raid, and who is coming?** Events with RSVP by role, recurrence, reminders, attendance.
3. **Who do we have?** A roster with game roles and weekly availability.

Everything else a guild does (chat, announcements, polls, files) Discord already does better.
Guild Manager wins by being the best at these three, not by having seventeen tabs.

## Modules after the overhaul

| Module | Keeps | Adds |
|---|---|---|
| **Home** | today's dashboard | next spawns, next events, who's online, at a glance; mobile-first |
| **Timers** | interval / fixed / weekly / biweekly / twice-daily bosses, kill logging, alerts, DND, webhooks, import/export, templates, kill history | spawn **windows** (min–max respawn), per-boss location/channel note, "next up" ordering, a **public read-only timer page** to pin in Discord, per-member timezone display |
| **Events** | create, RSVP, attendance, recurrence, reminders, start/end notices, event templates, attendance report | **RSVP by role** (tank / healer / DPS / support, editable labels), sign-up caps, week view, iCal export |
| **Roster** | members, roles, kick/leave/transfer, notes, availability grid, join requests, invite settings | **game role / class field** per member, availability shown next to events |
| **Loot & Points** (optional, off by default) | loot log, DKP ledger, awards, decay, wishlist, auctions | nothing new; toggled per team in Settings so guilds that don't run DKP never see it |
| **Settings** | webhooks, notifications, rules, cleanup, customization | module toggles |

## Cut

Removed from the front end first; worker routes deleted in the cleanup milestone.

| Tab | Why |
|---|---|
| Chat | Discord. Also the only endpoint polled every few seconds. |
| Announcements | Discord. |
| Polls | Discord has native polls. |
| Files | Discord attachments; R2 cost and abuse surface for near-zero use. |
| Wars | Game-specific (GvG log). If wanted later it is an event type with a result field. |
| Matches | Inter-team challenges need both guilds on the platform; no network to make it useful. |
| Performance | Niche stat logging; guilds that want it use spreadsheets or game addons. |
| Recruitment | Niche; recruiting happens on Discord servers and game forums. |
| Analytics | Charts over the cut features. Kill history and attendance report stay inside Timers and Events. |
| Rosters (lineup builder) | Returns in M3 as a per-event lineup inside Events, where a raid lineup actually belongs. |

Data in cut tables is left in D1 untouched until the cleanup milestone; nothing is deleted on the
first pass, the tabs just disappear.

## Premium after the cut

Most current premium gates are on cut features (chat reactions, analytics, auctions, wishlist,
custom role names, CSV export). Premium needs redefining; proposal, to decide before M5:

- Free: 1 team, 5 members, up to 10 timers, 1 webhook.
- Premium: unlimited teams and members, per-channel webhooks, boss templates, public timer page,
  kill history, attendance report, iCal, Loot & Points module.
- Until M5 the public timer page is ungated (it shipped in M2 without a premium check).

## Visual direction

- **Mobile-first.** The main use is checking a timer on a phone mid-raid. Everything must work
  at 360px wide before it is styled for desktop.
- **Top nav with 4–5 modules**, not a 17-item sidebar. Team switcher in the header.
- **Timer cards with a countdown ring/bar** and a clear state (waiting / window open / spawned).
- **Dark by default**, light theme kept. One token set in `css/tokens.css`, components in
  `css/components.css`, one stylesheet per module.
- Readable type scale, 8px spacing grid, consistent buttons/inputs/cards/modals/toasts.
- The visuals are designed in the browser and reviewed by screenshot, not described in prose.

## Architecture during the overhaul

- Each rebuilt module becomes a real **ES module** (`js/modules/<name>.js`) with its own state and
  explicit imports; inline `onclick` handlers are replaced by event delegation inside the module.
  The classic-script files from the 2026-09-22 split are deleted module by module as they are replaced.
- No framework, no build step (GitHub Pages serves files as-is). Template literals + a tiny
  `html` helper for escaping.
- `index.html` gets `?v=` cache-busting on its script and style tags, bumped per release.
- Worker: unchanged API shapes for kept features. New endpoints (public timer page, RSVP roles,
  spawn windows) are added to the existing route modules. Cut routes are deleted in M6.
- Every milestone is verified in Chrome on the same-origin local harness (page + `wrangler dev`)
  before it is pushed. The replay harness covers worker changes.

## Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Plan locked (this file), cut list confirmed | committed |
| M1 | **Shell + design system**: tokens, components, top nav, team switcher, Home; cut tabs hidden | DONE 2026-09-22: new shell renders every kept tab; verified desktop + 390/360px |
| M2 | **Timers rebuild**: module, new cards, spawn windows, next-up ordering, public timer page | DONE 2026-09-22: `js/modules/timers.js` (ES module), dense rows w/ countdown ring, location, spawn windows, edit endpoint, `timers.html` public page; verified desktop + phone with 20 bosses |
| M3 | **Events rebuild**: module, RSVP by role, caps, week view, iCal | as above |
| M4 | **Roster rebuild**: members + game role + availability; Settings with module toggles | as above |
| M5 | **Loot & Points** as an optional module; premium redefinition | toggle works; premium gates moved |
| M6 | **Cleanup**: delete cut front-end files and worker routes, drop cut tables' data export path, final polish | repo has no dead code; README updated |

Each milestone is one push (page) and, when needed, one `wrangler deploy` (worker).
