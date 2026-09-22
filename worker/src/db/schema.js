// Schema creation + idempotent migrations. Runs once per isolate.

let _dbInit = null; // per-isolate memo; reset to null on failure so the next request retries

export function ensureSchema(env) {
  if (!_dbInit) _dbInit = initDB(env.DB).catch(e => { _dbInit = null; console.error('initDB error:', e); });
  return _dbInit;
}

async function initDB(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      discord_id TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      avatar TEXT,
      premium INTEGER DEFAULT 0,
      premium_type TEXT,
      premium_until INTEGER,
      ls_customer_id TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS teams (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      owner_id TEXT NOT NULL,
      invite_code TEXT UNIQUE NOT NULL,
      max_members INTEGER DEFAULT 5,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS team_members (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      role TEXT DEFAULT 'member',
      joined_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS bosses (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      interval_ms INTEGER,
      fixed_time TEXT,
      weekly_day INTEGER,
      weekly_time TEXT,
      biweekly_days TEXT,
      alert_minutes INTEGER DEFAULT 5,
      auto_reset_minutes INTEGER DEFAULT 5,
      next_spawn INTEGER NOT NULL,
      status TEXT DEFAULT 'waiting',
      spawned_at INTEGER,
      auto_reset_at INTEGER,
      last_death INTEGER,
      warned INTEGER DEFAULT 0,
      spawn_notified INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      event_type TEXT DEFAULT 'other',
      event_time INTEGER NOT NULL,
      duration_minutes INTEGER DEFAULT 60,
      created_by TEXT NOT NULL,
      reminder_sent INTEGER DEFAULT 0,
      start_notified INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_rsvps (
      event_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      status TEXT DEFAULT 'going',
      responded_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (event_id, user_id),
      FOREIGN KEY (event_id) REFERENCES events(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_attendance (
      event_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      attended INTEGER DEFAULT 0,
      PRIMARY KEY (event_id, user_id),
      FOREIGN KEY (event_id) REFERENCES events(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS team_settings (
      team_id TEXT PRIMARY KEY,
      webhook_url TEXT,
      on_warning INTEGER DEFAULT 1,
      on_spawn INTEGER DEFAULT 1,
      on_announcement INTEGER DEFAULT 1,
      timezone TEXT DEFAULT 'Asia/Manila',
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS announcements (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      pinned INTEGER DEFAULT 0,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS member_activity (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      last_seen INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_loot (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      boss_id TEXT,
      boss_name TEXT NOT NULL,
      item_name TEXT NOT NULL,
      recipient_id TEXT NOT NULL,
      dkp_cost INTEGER DEFAULT 0,
      noted_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (recipient_id) REFERENCES users(id),
      FOREIGN KEY (noted_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_ledger (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS member_availability (
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      day INTEGER NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      PRIMARY KEY (team_id, user_id, day, start_time),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
  ]);
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS member_notes (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      target_user_id TEXT NOT NULL,
      author_id TEXT NOT NULL,
      note TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (target_user_id) REFERENCES users(id),
      FOREIGN KEY (author_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS chat_reactions (
      message_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      emoji TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (message_id, user_id, emoji),
      FOREIGN KEY (message_id) REFERENCES chat_messages(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_kill_log (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      boss_id TEXT NOT NULL,
      boss_name TEXT NOT NULL,
      killed_at INTEGER NOT NULL,
      killed_by TEXT,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS boss_templates (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      game TEXT NOT NULL,
      bosses TEXT NOT NULL,
      is_global INTEGER DEFAULT 0,
      created_by TEXT,
      created_at INTEGER DEFAULT (unixepoch())
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS event_templates (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      event_type TEXT DEFAULT 'other',
      duration_minutes INTEGER DEFAULT 60,
      recurrence TEXT,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS loot_wishlist (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      item_name TEXT NOT NULL,
      boss_name TEXT,
      priority INTEGER DEFAULT 1,
      fulfilled INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_auctions (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      item_name TEXT NOT NULL,
      boss_name TEXT,
      started_by TEXT NOT NULL,
      status TEXT DEFAULT 'open',
      min_bid INTEGER DEFAULT 0,
      winner_id TEXT,
      winning_bid INTEGER,
      expires_at INTEGER,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS dkp_bids (
      id TEXT PRIMARY KEY,
      auction_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount INTEGER NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (auction_id) REFERENCES dkp_auctions(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS analytics_snapshots (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      snapshot_type TEXT NOT NULL,
      snapshot_data TEXT NOT NULL,
      snapshot_date INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS custom_roles (
      team_id TEXT NOT NULL,
      base_role TEXT NOT NULL,
      display_name TEXT NOT NULL,
      color TEXT,
      PRIMARY KEY (team_id, base_role),
      FOREIGN KEY (team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS chat_messages (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS war_log (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      opponent TEXT NOT NULL,
      result TEXT NOT NULL,
      event_type TEXT DEFAULT 'gvg',
      score_us INTEGER,
      score_them INTEGER,
      notes TEXT,
      war_date INTEGER DEFAULT (unixepoch()),
      logged_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (logged_by) REFERENCES users(id)
    )`),
  ]);

  // Phase 10 tables: Polls, Roster, Performance, Recruitment
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS polls (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      question TEXT NOT NULL,
      poll_type TEXT DEFAULT 'single',
      created_by TEXT NOT NULL,
      closed INTEGER DEFAULT 0,
      expires_at INTEGER,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS poll_options (
      id TEXT PRIMARY KEY,
      poll_id TEXT NOT NULL,
      label TEXT NOT NULL,
      sort_order INTEGER DEFAULT 0,
      FOREIGN KEY (poll_id) REFERENCES polls(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id TEXT NOT NULL,
      option_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      PRIMARY KEY (poll_id, option_id, user_id),
      FOREIGN KEY (poll_id) REFERENCES polls(id),
      FOREIGN KEY (option_id) REFERENCES poll_options(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS rosters (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      name TEXT NOT NULL,
      event_id TEXT,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS roster_slots (
      id TEXT PRIMARY KEY,
      roster_id TEXT NOT NULL,
      role_name TEXT NOT NULL,
      user_id TEXT,
      sort_order INTEGER DEFAULT 0,
      FOREIGN KEY (roster_id) REFERENCES rosters(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS performance_entries (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      event_label TEXT NOT NULL,
      stat_name TEXT NOT NULL,
      stat_value REAL NOT NULL,
      logged_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (logged_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS recruitment_posts (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      role_needed TEXT,
      status TEXT DEFAULT 'open',
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (created_by) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS recruitment_applications (
      id TEXT PRIMARY KEY,
      post_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by TEXT,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (post_id) REFERENCES recruitment_posts(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS matches (
      id TEXT PRIMARY KEY,
      challenger_team_id TEXT NOT NULL,
      challenged_team_id TEXT NOT NULL,
      challenger_name TEXT NOT NULL,
      challenged_name TEXT NOT NULL,
      match_type TEXT DEFAULT 'gvg',
      scheduled_time INTEGER,
      message TEXT,
      status TEXT DEFAULT 'pending',
      result_challenger INTEGER,
      result_challenged INTEGER,
      winner_team_id TEXT,
      completed_by TEXT,
      created_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (challenger_team_id) REFERENCES teams(id),
      FOREIGN KEY (challenged_team_id) REFERENCES teams(id)
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS team_files (
      id TEXT PRIMARY KEY,
      team_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      content_type TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      created_at INTEGER DEFAULT (unixepoch()),
      FOREIGN KEY (team_id) REFERENCES teams(id),
      FOREIGN KEY (uploaded_by) REFERENCES users(id)
    )`),
  ]);

  // Run migrations (each one is idempotent via catch).
  // Probes MUST include the newest added column/table — otherwise DBs that passed
  // older probes will silently miss newer migrations forever.
  const needsMigrations = await db.prepare("SELECT premium FROM users LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT accent_color FROM team_settings LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT trial_started FROM users LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT google_id FROM users LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT invites_enabled FROM team_settings LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT 1 FROM join_requests LIMIT 1").first().then(() => false).catch(() => true)
    || await db.prepare("SELECT public_token FROM team_settings LIMIT 1").first().then(() => false).catch(() => true);
  if (needsMigrations) {
    const migrations = [
      'ALTER TABLE users ADD COLUMN premium INTEGER DEFAULT 0',
      'ALTER TABLE users ADD COLUMN premium_type TEXT',
      'ALTER TABLE users ADD COLUMN premium_until INTEGER',
      'ALTER TABLE users ADD COLUMN ls_customer_id TEXT',
      'ALTER TABLE team_settings ADD COLUMN on_announcement INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN on_event INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN on_war INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN event_reminder_minutes INTEGER DEFAULT 15',
      'ALTER TABLE team_settings ADD COLUMN inactive_days INTEGER DEFAULT 7',
      'ALTER TABLE team_settings ADD COLUMN default_event_duration INTEGER DEFAULT 60',
      'ALTER TABLE team_settings ADD COLUMN team_description TEXT',
      'ALTER TABLE team_settings ADD COLUMN members_create_events INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN auto_delete_events_days INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN auto_delete_chat_days INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN starting_dkp INTEGER DEFAULT 0',
      'ALTER TABLE events ADD COLUMN recurrence TEXT',
      'ALTER TABLE events ADD COLUMN parent_event_id TEXT',
      'ALTER TABLE events ADD COLUMN end_notified INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN webhook_boss TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_events TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_wars TEXT',
      'ALTER TABLE team_settings ADD COLUMN webhook_announcements TEXT',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_enabled INTEGER DEFAULT 0',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_percent INTEGER DEFAULT 10',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_inactive_days INTEGER DEFAULT 14',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_interval_days INTEGER DEFAULT 7',
      'ALTER TABLE team_settings ADD COLUMN dkp_decay_last_run INTEGER',
      'ALTER TABLE team_settings ADD COLUMN accent_color TEXT',
      'ALTER TABLE team_settings ADD COLUMN team_icon TEXT',
      'ALTER TABLE users ADD COLUMN trial_started INTEGER',
      'ALTER TABLE users ADD COLUMN trial_used INTEGER DEFAULT 0',
      'ALTER TABLE users ADD COLUMN google_id TEXT',
      'ALTER TABLE users ADD COLUMN auth_type TEXT DEFAULT "discord"',
      'ALTER TABLE bosses ADD COLUMN auto_reset_minutes INTEGER DEFAULT 5',
      'ALTER TABLE team_settings ADD COLUMN invites_enabled INTEGER DEFAULT 1',
      'ALTER TABLE team_settings ADD COLUMN invite_approval INTEGER DEFAULT 0',
      'ALTER TABLE bosses ADD COLUMN window_ms INTEGER DEFAULT 0',
      'ALTER TABLE bosses ADD COLUMN location TEXT',
      'ALTER TABLE team_settings ADD COLUMN public_token TEXT',
      `CREATE TABLE IF NOT EXISTS join_requests (
        id TEXT PRIMARY KEY,
        team_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        username TEXT,
        status TEXT DEFAULT 'pending',
        created_at INTEGER DEFAULT (unixepoch()),
        resolved_by TEXT,
        resolved_at INTEGER,
        FOREIGN KEY (team_id) REFERENCES teams(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`,
    ];
    // prepare().run() — NOT db.exec(): D1's exec() splits on newlines, so the
    // multi-line CREATE TABLE above could never succeed and the probe failed forever.
    for (const sql of migrations) await db.prepare(sql).run().catch(() => {});
  }
}
