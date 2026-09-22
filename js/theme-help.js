// Theme toggle (persisted) and the Help & Guide modal

// Theme
function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'light' ? null : 'light';
    if (next) document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    localStorage.setItem('gm_theme', next || 'dark');
    document.getElementById('themeBtn').textContent = next === 'light' ? '☀️' : '🌙';
}
// Apply saved theme
(function() {
    const saved = localStorage.getItem('gm_theme');
    if (saved === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
        document.getElementById('themeBtn').textContent = '☀️';
    }
})();

// Help modal
function showHelpModal() {
    const sections = [
        { icon: '📊', title: 'Dashboard', text: 'Overview of your team at a glance — member count, upcoming events, active boss timers, recent activity, and quick stats.' },
        { icon: '💬', title: 'Chat', text: 'Real-time team chat. Send messages, react with emojis (Premium), and coordinate with your team. Messages are stored per-team.' },
        { icon: '📢', title: 'Announcements', text: 'Post important announcements that stay pinned for the whole team. Only officers and the leader can create announcements. Great for rules, updates, or schedules.' },
        { icon: '⏱️', title: 'Boss Timers', text: 'Track boss respawn timers. Add bosses with interval, daily, weekly, or biweekly respawn types. When a boss dies, click the skull to start the death timer. Get Discord webhook notifications when bosses are about to spawn. Premium users can save boss templates and view kill history.' },
        { icon: '📅', title: 'Events', text: 'Schedule team events like scrims, raids, GvG, or custom events. Set date, time, and description. Members can RSVP as Going, Maybe, or Not Going. Supports recurring events (daily, weekly, biweekly, monthly).' },
        { icon: '👥', title: 'Members', text: 'View all team members with their roles. The leader can promote/demote members (Member → Officer → Leader) or kick members. Share the invite code to recruit new members.' },
        { icon: '🗡️', title: 'Loot', text: 'Track item drops and assign them to team members. Log who got what loot and when. Premium users can set up a loot wishlist for members to claim priority on items.' },
        { icon: '💎', title: 'Points (' + ptsName() + ')', text: 'A customizable points system (default: DKP) to fairly distribute loot and reward participation. Award points for attendance, deduct when loot is claimed. Rename it in Settings → "Points System Name" to fit your game (e.g. Credits, Rep, Contribution). Premium: auctions and point decay.' },
        { icon: '⚔️', title: 'Wars', text: 'Log war results against other teams. Track wins, losses, and draws. Add notes and scores per war. View your team\'s overall war statistics and win rate.' },
        { icon: '📆', title: 'Availability', text: 'Weekly availability calendar. Each member marks the days they\'re available so the team can plan events around everyone\'s schedule.' },
        { icon: '📊', title: 'Polls', text: 'Create polls to let your team vote on decisions — single or multi-choice. Any member can create polls, leaders/officers can close them. Click a bar to vote.' },
        { icon: '📋', title: 'Rosters', text: 'Build team lineups for events or boss fights. Define roles (Tank, Healer, DPS, etc.) and assign members to each slot. Leaders/officers create and edit rosters.' },
        { icon: '🏆', title: 'Performance', text: 'Track player stats per event — kills, deaths, damage, healing, or any custom stat. Leaders/officers log stats, and the averages table shows each member\'s performance over time.' },
        { icon: '📝', title: 'Recruitment', text: 'Post openings for your team. Specify the role needed and requirements. Other members can apply with a message. Leaders/officers review and accept or reject applications.' },
        { icon: '📁', title: 'Files', text: 'Upload and share files with your team — screenshots, guides, spreadsheets, strategy images. Max 5MB per file. Free teams get 100MB storage, premium teams get 500MB. Preview images directly, or download any file. Leaders/officers can delete files.' },
        { icon: '🏟️', title: 'Matches', text: 'Schedule matches against other teams on the platform. Search for a team by name, send a challenge with a match type and time. The other team accepts or declines. After the match, log scores to determine the winner. Discord webhook notifications are sent for challenges and acceptances.' },
        { icon: '📈', title: 'Analytics', text: 'Premium feature — detailed charts and stats about your team\'s activity, event attendance, points distribution, and more.' },
        { icon: '⚙️', title: 'Settings', text: 'Configure your team — set description, timezone, Discord webhook URL for notifications, toggle which events send notifications, manage member permissions, and customize roles with colors and icons.' },
        { icon: '🔗', title: 'Discord Notifications', text: 'Connect a Discord webhook URL in Settings to get automatic notifications for boss spawns, new events, announcements, and war results directly in your Discord channel.' },
        { icon: '⭐', title: 'Premium', text: 'Free tier: 1 team, 5 members. Premium: unlimited teams, 50 members, chat reactions, boss templates & history, loot wishlist, points auctions & decay, analytics, CSV export, custom role colors/icons, and no watermark.' },
    ];
    let html = `<div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)this.remove()">
        <div class="card" style="width:550px;max-width:90vw;max-height:85vh;margin:0;overflow:hidden;display:flex;flex-direction:column">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                <h2 style="font-size:1.3em">❓ Help & Guide</h2>
                <button class="btn" onclick="this.closest('[style*=fixed]').remove()" style="padding:4px 10px;background:var(--bg-input);color:var(--text-muted);font-size:1.1em">✕</button>
            </div>
            <p style="color:var(--text-muted);font-size:0.85em;margin-bottom:14px">Click any section to learn more about it.</p>
            <div style="overflow-y:auto;flex:1;padding-right:4px">`;
    for (const s of sections) {
        html += `<details style="margin-bottom:6px;border:1px solid var(--border);border-radius:8px;overflow:hidden">
            <summary style="padding:10px 14px;cursor:pointer;background:var(--bg-item);font-weight:600;font-size:0.95em;list-style:none;display:flex;align-items:center;gap:8px;user-select:none">
                <span style="font-size:1.15em">${s.icon}</span> ${s.title}
                <span style="margin-left:auto;color:var(--text-dim);font-size:0.8em">▼</span>
            </summary>
            <div style="padding:10px 14px;font-size:0.88em;color:var(--text-muted);line-height:1.6;background:var(--bg-card)">${s.text}</div>
        </details>`;
    }
    html += `</div>
            <div style="margin-top:12px;padding-top:10px;border-top:1px solid var(--border);font-size:0.78em;color:var(--text-dim);text-align:center">
                Click outside the modal or press ✕ to close
            </div>
        </div>
    </div>`;
    document.getElementById('deathModal').innerHTML = html;
}
