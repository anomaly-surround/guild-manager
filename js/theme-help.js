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
        { icon: '🏠', title: 'Home', text: 'The next boss spawns, upcoming events and who is online, at a glance.' },
        { icon: '⏱️', title: 'Timers', text: 'Shared boss timers: interval, daily, weekly, twice-daily or twice-weekly rules, optional spawn windows and a location note. Press Killed when a boss dies (or set the exact kill time) and the next spawn is recalculated for everyone. Discord gets a warning before each spawn. Premium: boss templates, kill history and a public read-only timer page you can pin in Discord.' },
        { icon: '📅', title: 'Events', text: 'Raids, GvGs, scrims and meetings. Members RSVP Going / Maybe / Can\'t and pick their role (Tank, Healer, DPS…), so officers see the split at a glance. Sign-up caps, recurring events, a week view and per-event lineups. Officers mark attendance afterwards. Premium: event templates, attendance report and a calendar feed.' },
        { icon: '👥', title: 'Roster', text: 'Everyone on the team with their class or role, who is online, and weekly availability so you can pick raid times. Officers keep private notes, manage roles and review join requests.' },
        { icon: '💎', title: 'Loot & Points', text: 'Optional module (turn it on in Settings). Log who received which drop, run a points system (default: DKP, rename it in Settings) for fair loot distribution. Premium: wishlist, auctions and point decay.' },
        { icon: '⚙️', title: 'Settings', text: 'Discord webhooks and which alerts to send, invite rules, event RSVP roles, timezone, modules, points name, and ownership transfer.' },
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
