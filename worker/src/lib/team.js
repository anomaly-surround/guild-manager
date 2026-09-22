// Team membership + premium checks (shared by every team route)

export async function requireTeamMember(env, teamId, userId) {
  return env.DB.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
    .bind(teamId, userId).first();
}

export async function isPremiumTeam(env, teamId) {
  try {
    const team = await env.DB.prepare('SELECT owner_id FROM teams WHERE id = ?').bind(teamId).first();
    if (!team) return false;
    const owner = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(team.owner_id).first();
    if (!owner) return false;
    if (owner.premium) {
      if (String(owner.premium_type || '').trim().toLowerCase() === 'lifetime') return true;
      if (owner.premium_until && owner.premium_until > Math.floor(Date.now() / 1000)) return true;
      if (!owner.premium_type && !owner.premium_until) return true;
    }
    if (owner.trial_started && !owner.trial_used) {
      const trialEnd = owner.trial_started + 7 * 86400;
      if (Math.floor(Date.now() / 1000) < trialEnd) return true;
    }
    return false;
  } catch(e) {
    console.error('isPremiumTeam error:', e);
    return false;
  }
}
