# Dropping the cut tables from production D1

The overhaul (M0–M8) removed Chat, Announcements, Polls, Files, Wars, Matches, Performance,
Recruitment, Analytics and Custom Roles. As of commit `M8c` nothing in `worker/src` reads,
writes, creates or deletes from their tables, but the tables still exist in the production
database with whatever data teams left in them. Dropping them is irreversible, so it is a
manual step, run once, after the worker that no longer references them is live.

Tables: `announcements chat_messages chat_reactions analytics_snapshots custom_roles war_log
polls poll_options poll_votes rosters roster_slots performance_entries recruitment_posts
recruitment_applications matches team_files`

## Order

1. Deploy the worker (`M8c` or later) so no code path touches these tables.
2. Back up the whole database (safe, read-only):

```
cd C:\Users\anomaly2\Desktop\Claude\guild-manager\worker; npx wrangler d1 export guild-manager --remote --output=..\backups\d1-before-drop-20260923.sql
```

3. Drop (irreversible):

```
cd C:\Users\anomaly2\Desktop\Claude\guild-manager\worker; npx wrangler d1 execute guild-manager --remote --command "DROP TABLE IF EXISTS chat_reactions; DROP TABLE IF EXISTS chat_messages; DROP TABLE IF EXISTS poll_votes; DROP TABLE IF EXISTS poll_options; DROP TABLE IF EXISTS polls; DROP TABLE IF EXISTS roster_slots; DROP TABLE IF EXISTS rosters; DROP TABLE IF EXISTS recruitment_applications; DROP TABLE IF EXISTS recruitment_posts; DROP TABLE IF EXISTS announcements; DROP TABLE IF EXISTS analytics_snapshots; DROP TABLE IF EXISTS custom_roles; DROP TABLE IF EXISTS war_log; DROP TABLE IF EXISTS performance_entries; DROP TABLE IF EXISTS matches; DROP TABLE IF EXISTS team_files;"
```

Children are dropped before parents so FOREIGN KEY checks never fire.

## Leftovers that are fine to leave

- `team_settings` still has columns from cut features (`auto_delete_chat_days`, `webhook_announcements`,
  `starting_dkp`, `default_event_duration`, `inactive_days`, `accent_color`). SQLite column drops are
  awkward and the columns cost nothing; the ALTER migrations for them stay idempotent.
- The R2 bucket `guild-manager-files` may still hold uploads from the old Files tab. The `team_files`
  rows were the only index into it, so after the drop those objects are orphans. Empty the bucket from
  the Cloudflare dashboard whenever convenient, and the `FILES` binding in `wrangler.toml` can go with it.
