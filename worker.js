/**
 * Guild Manager - Cloudflare Worker
 * Phase 1: Discord OAuth + Team creation + Invite system
 *
 * Bindings: DB (D1), DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, JWT_SECRET
 */

// --- Helpers ---

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

// Simple JWT-like token using HMAC-SHA256
async function createToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data)))));
  return `${data}.${sig}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, body, sig] = token.split('.');
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const expected = new Uint8Array(atob(sig).split('').map(c => c.charCodeAt(0)));
    const valid = await crypto.subtle.verify('HMAC', key, expected, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function getUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return verifyToken(token, env.JWT_SECRET);
}

function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// --- Database setup ---

async function initDB(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      discord_id TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      avatar TEXT,
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
  ]);
}

// --- Routes ---

async function handleRequest(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders() });
  }

  const url = new URL(request.url);
  const path = url.pathname;

  // Init DB on first request
  await initDB(env.DB);

  // --- Auth routes ---

  // GET /auth/login — redirect to Discord OAuth
  if (path === '/auth/login') {
    const redirect = `https://discord.com/api/oauth2/authorize?client_id=${env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}&response_type=code&scope=identify`;
    return Response.redirect(redirect, 302);
  }

  // GET /auth/callback — Discord OAuth callback
  if (path === '/auth/callback') {
    const code = url.searchParams.get('code');
    if (!code) return json({ error: 'No code provided' }, 400);

    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: url.origin + '/auth/callback',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return json({ error: 'OAuth failed' }, 400);

    // Get Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userRes.json();
    if (!discordUser.id) return json({ error: 'Failed to get user' }, 400);

    // Upsert user in DB
    const userId = crypto.randomUUID();
    const existing = await env.DB.prepare('SELECT id FROM users WHERE discord_id = ?').bind(discordUser.id).first();

    let finalUserId;
    if (existing) {
      finalUserId = existing.id;
      await env.DB.prepare('UPDATE users SET username = ?, avatar = ? WHERE id = ?')
        .bind(discordUser.username, discordUser.avatar, existing.id).run();
    } else {
      finalUserId = userId;
      await env.DB.prepare('INSERT INTO users (id, discord_id, username, avatar) VALUES (?, ?, ?, ?)')
        .bind(userId, discordUser.id, discordUser.username, discordUser.avatar).run();
    }

    // Create JWT
    const jwt = await createToken({
      userId: finalUserId,
      discordId: discordUser.id,
      username: discordUser.username,
    }, env.JWT_SECRET);

    // Redirect to frontend with token
    const frontendUrl = 'https://anomaly-surround.github.io/guild-manager';
    return Response.redirect(`${frontendUrl}?token=${jwt}`, 302);
  }

  // GET /auth/me — get current user
  if (path === '/auth/me') {
    const user = await getUser(request, env);
    if (!user) return json({ error: 'Not logged in' }, 401);
    const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.userId).first();
    if (!dbUser) return json({ error: 'User not found' }, 404);
    return json({
      id: dbUser.id,
      username: dbUser.username,
      avatar: dbUser.avatar,
      discordId: dbUser.discord_id,
    });
  }

  // --- Protected routes (require auth) ---
  const user = await getUser(request, env);
  if (!user && path.startsWith('/api/')) {
    return json({ error: 'Unauthorized' }, 401);
  }

  // GET /api/teams — list user's teams
  if (path === '/api/teams' && request.method === 'GET') {
    const teams = await env.DB.prepare(`
      SELECT t.*, tm.role,
        (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) as member_count
      FROM teams t
      JOIN team_members tm ON tm.team_id = t.id AND tm.user_id = ?
      ORDER BY t.created_at DESC
    `).bind(user.userId).all();
    return json({ teams: teams.results });
  }

  // POST /api/teams — create a team
  if (path === '/api/teams' && request.method === 'POST') {
    const body = await request.json();
    if (!body.name || !body.name.trim()) return json({ error: 'Name required' }, 400);

    // Check team limit (free = 1 team)
    const teamCount = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM teams WHERE owner_id = ?'
    ).bind(user.userId).first();
    if (teamCount.count >= 1) {
      return json({ error: 'Free tier: 1 team max. Upgrade for more.' }, 403);
    }

    const teamId = crypto.randomUUID();
    const inviteCode = generateInviteCode();

    await env.DB.batch([
      env.DB.prepare('INSERT INTO teams (id, name, owner_id, invite_code) VALUES (?, ?, ?, ?)')
        .bind(teamId, body.name.trim(), user.userId, inviteCode),
      env.DB.prepare('INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)')
        .bind(teamId, user.userId, 'leader'),
    ]);

    return json({ team: { id: teamId, name: body.name.trim(), invite_code: inviteCode } });
  }

  // GET /api/teams/:id — team detail with members
  const teamMatch = path.match(/^\/api\/teams\/([^/]+)$/);
  if (teamMatch && request.method === 'GET') {
    const teamId = teamMatch[1];

    // Check membership
    const membership = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!membership) return json({ error: 'Not a member' }, 403);

    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ?').bind(teamId).first();
    if (!team) return json({ error: 'Team not found' }, 404);

    const members = await env.DB.prepare(`
      SELECT u.id, u.username, u.avatar, u.discord_id, tm.role, tm.joined_at
      FROM team_members tm
      JOIN users u ON u.id = tm.user_id
      WHERE tm.team_id = ?
      ORDER BY
        CASE tm.role WHEN 'leader' THEN 0 WHEN 'officer' THEN 1 ELSE 2 END,
        tm.joined_at ASC
    `).bind(teamId).all();

    return json({
      team: { ...team, my_role: membership.role },
      members: members.results,
    });
  }

  // DELETE /api/teams/:id — delete team (leader only)
  const deleteTeamMatch = path.match(/^\/api\/teams\/([^/]+)$/);
  if (deleteTeamMatch && request.method === 'DELETE') {
    const teamId = deleteTeamMatch[1];
    const team = await env.DB.prepare('SELECT * FROM teams WHERE id = ? AND owner_id = ?')
      .bind(teamId, user.userId).first();
    if (!team) return json({ error: 'Not the owner' }, 403);

    await env.DB.batch([
      env.DB.prepare('DELETE FROM team_members WHERE team_id = ?').bind(teamId),
      env.DB.prepare('DELETE FROM teams WHERE id = ?').bind(teamId),
    ]);
    return json({ ok: true });
  }

  // POST /api/teams/:id/members/role — change member role (leader/officer only)
  const roleMatch = path.match(/^\/api\/teams\/([^/]+)\/members\/role$/);
  if (roleMatch && request.method === 'POST') {
    const teamId = roleMatch[1];
    const body = await request.json();

    const myRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!myRole || (myRole.role !== 'leader' && myRole.role !== 'officer')) {
      return json({ error: 'No permission' }, 403);
    }

    // Can't change leader role unless you're the leader
    if (body.role === 'leader' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can promote to leader' }, 403);
    }

    await env.DB.prepare('UPDATE team_members SET role = ? WHERE team_id = ? AND user_id = ?')
      .bind(body.role, teamId, body.userId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/kick — kick member (leader/officer only)
  const kickMatch = path.match(/^\/api\/teams\/([^/]+)\/kick$/);
  if (kickMatch && request.method === 'POST') {
    const teamId = kickMatch[1];
    const body = await request.json();

    const myRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, user.userId).first();
    if (!myRole || (myRole.role !== 'leader' && myRole.role !== 'officer')) {
      return json({ error: 'No permission' }, 403);
    }

    // Can't kick leader
    const targetRole = await env.DB.prepare(
      'SELECT role FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(teamId, body.userId).first();
    if (targetRole?.role === 'leader') return json({ error: "Can't kick the leader" }, 403);
    if (targetRole?.role === 'officer' && myRole.role !== 'leader') {
      return json({ error: 'Only leader can kick officers' }, 403);
    }

    await env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, body.userId).run();
    return json({ ok: true });
  }

  // POST /api/teams/:id/leave — leave team
  const leaveMatch = path.match(/^\/api\/teams\/([^/]+)\/leave$/);
  if (leaveMatch && request.method === 'POST') {
    const teamId = leaveMatch[1];

    const team = await env.DB.prepare('SELECT owner_id FROM teams WHERE id = ?').bind(teamId).first();
    if (team?.owner_id === user.userId) {
      return json({ error: 'Leader cannot leave. Delete the team or transfer ownership.' }, 400);
    }

    await env.DB.prepare('DELETE FROM team_members WHERE team_id = ? AND user_id = ?')
      .bind(teamId, user.userId).run();
    return json({ ok: true });
  }

  // POST /api/invite/:code — join team via invite code
  const inviteMatch = path.match(/^\/api\/invite\/([^/]+)$/);
  if (inviteMatch && request.method === 'POST') {
    const code = inviteMatch[1];

    const team = await env.DB.prepare('SELECT * FROM teams WHERE invite_code = ?').bind(code).first();
    if (!team) return json({ error: 'Invalid invite code' }, 404);

    // Check if already a member
    const existing = await env.DB.prepare(
      'SELECT 1 FROM team_members WHERE team_id = ? AND user_id = ?'
    ).bind(team.id, user.userId).first();
    if (existing) return json({ error: 'Already a member', team: { id: team.id, name: team.name } }, 400);

    // Check member limit
    const count = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM team_members WHERE team_id = ?'
    ).bind(team.id).first();
    if (count.count >= team.max_members) {
      return json({ error: `Team is full (${team.max_members} members max)` }, 403);
    }

    await env.DB.prepare('INSERT INTO team_members (team_id, user_id, role) VALUES (?, ?, ?)')
      .bind(team.id, user.userId, 'member').run();

    return json({ ok: true, team: { id: team.id, name: team.name } });
  }

  // GET /api/invite/:code — get invite info (public)
  if (inviteMatch && request.method === 'GET') {
    const code = inviteMatch[1];
    const team = await env.DB.prepare('SELECT id, name FROM teams WHERE invite_code = ?').bind(code).first();
    if (!team) return json({ error: 'Invalid invite code' }, 404);
    const count = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM team_members WHERE team_id = ?'
    ).bind(team.id).first();
    return json({ team: { name: team.name, members: count.count } });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};
