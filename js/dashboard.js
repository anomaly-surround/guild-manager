// Dashboard tab

// --- Dashboard ---

async function loadAndRenderDashboard() {
    teamTab = 'dashboard';
    renderTeamView();

    const el = document.getElementById('dashboardContent');
    if (!el) return;

    // Fetch all data in parallel with fallbacks
    const [eventsData, announcementsData, warsData, chatData] = await Promise.all([
        api('GET', `/api/teams/${currentTeamId}/events`).catch(() => ({})),
        api('GET', `/api/teams/${currentTeamId}/announcements`).catch(() => ({})),
        api('GET', `/api/teams/${currentTeamId}/wars`).catch(() => ({})),
        api('GET', `/api/teams/${currentTeamId}/chat?after=0`).catch(() => ({})),
    ]);

    const now = Date.now();
    const events = eventsData.events || [];
    const announcements = announcementsData.announcements || [];
    const wars = warsData.wars || [];
    const stats = warsData.stats || {};
    const messages = chatData.messages || [];
    const members = teamData.members || [];

    // Next boss spawn
    let nextBoss = null;
    const waitingBosses = teamBosses.filter(b => b.status === 'waiting' && b.next_spawn > now);
    if (waitingBosses.length > 0) {
        nextBoss = waitingBosses.sort((a, b) => a.next_spawn - b.next_spawn)[0];
    }
    const spawnedBosses = teamBosses.filter(b => b.status === 'spawned' || b.next_spawn <= now);

    // Next event
    const upcomingEvents = events.filter(e => e.event_time > now).sort((a, b) => a.event_time - b.event_time);
    const liveEvents = events.filter(e => e.event_time <= now && e.event_time + (e.duration_minutes || 60) * 60000 > now);

    // Latest announcement
    const latestAnnouncement = announcements[0];

    // Recent chat
    const recentMessages = messages.slice(-3);

    // Online members
    const nowSec = Math.floor(now / 1000);
    const onlineCount = members.filter(m => m.last_seen && (nowSec - m.last_seen) < 300).length;

    let html = '<div class="dash-grid">';

    // Boss Timers card
    html += `<div class="dash-card" onclick="teamTab='timers';renderTeamView()">
        <h4>Boss Timers</h4>`;
    if (spawnedBosses.length > 0) {
        html += `<div class="dash-value" style="color:#ef4444">${spawnedBosses.length} SPAWNED!</div>`;
        html += `<div class="dash-sub">${spawnedBosses.map(b => escapeHtml(b.name)).join(', ')}</div>`;
    } else if (nextBoss) {
        const remaining = nextBoss.next_spawn - now;
        html += `<div class="dash-value">${escapeHtml(nextBoss.name)}</div>`;
        html += `<div class="dash-sub">in ${formatTimeLong(remaining)}</div>`;
    } else {
        html += `<div class="dash-value" style="color:var(--text-dim)">No timers</div>`;
    }
    html += '</div>';

    // Events card
    html += `<div class="dash-card" onclick="teamTab='events';loadAndRenderEvents()">
        <h4>Events</h4>`;
    if (liveEvents.length > 0) {
        html += `<div class="dash-value" style="color:#ef4444">${escapeHtml(liveEvents[0].title)} — LIVE</div>`;
    } else if (upcomingEvents.length > 0) {
        const e = upcomingEvents[0];
        const eventDate = new Date(e.event_time);
        const dateStr = eventDate.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
        const timeStr = eventDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        html += `<div class="dash-value">${escapeHtml(e.title)}</div>`;
        html += `<div class="dash-sub">${dateStr} at ${timeStr}</div>`;
    } else {
        html += `<div class="dash-value" style="color:var(--text-dim)">No upcoming</div>`;
    }
    html += '</div>';

    // Announcements card
    html += `<div class="dash-card" onclick="loadAndRenderAnnouncements()">
        <h4>Latest Announcement</h4>`;
    if (latestAnnouncement) {
        html += `<div class="dash-value">${escapeHtml(latestAnnouncement.title)}</div>`;
        html += `<div class="dash-sub">by ${escapeHtml(latestAnnouncement.author_name)}</div>`;
    } else {
        html += `<div class="dash-value" style="color:var(--text-dim)">None yet</div>`;
    }
    html += '</div>';

    // Wars card
    html += `<div class="dash-card" onclick="loadAndRenderWars()">
        <h4>War Record</h4>`;
    const total = (stats.wins || 0) + (stats.losses || 0) + (stats.draws || 0);
    if (total > 0) {
        const winRate = Math.round(((stats.wins || 0) / total) * 100);
        html += `<div class="dash-value"><span style="color:#34d399">${stats.wins}W</span> / <span style="color:#ef4444">${stats.losses}L</span> / <span style="color:#f59e0b">${stats.draws}D</span></div>`;
        html += `<div class="dash-sub">${winRate}% win rate</div>`;
    } else {
        html += `<div class="dash-value" style="color:var(--text-dim)">No wars yet</div>`;
    }
    html += '</div>';

    // Members card
    html += `<div class="dash-card" onclick="teamTab='members';renderTeamView()">
        <h4>Members</h4>
        <div class="dash-value">${members.length} total</div>
        <div class="dash-sub"><span style="color:#34d399">${onlineCount} online</span></div>
    </div>`;

    // Chat card
    html += `<div class="dash-card" onclick="loadAndRenderChat()">
        <h4>Recent Chat</h4>`;
    if (recentMessages.length > 0) {
        for (const m of recentMessages) {
            html += `<div class="dash-sub" style="margin-top:2px"><b>${escapeHtml(m.username)}:</b> ${escapeHtml(m.message).substring(0, 40)}${m.message.length > 40 ? '...' : ''}</div>`;
        }
    } else {
        html += `<div class="dash-value" style="color:var(--text-dim)">No messages</div>`;
    }
    html += '</div>';

    html += '</div>';
    el.innerHTML = html;
}
