// Home: next spawns, upcoming events and the roster at a glance.

async function loadAndRenderHome() {
    teamTab = 'home';
    renderTeamView();

    const el = document.getElementById('homeContent');
    if (!el) return;

    const eventsData = await api('GET', `/api/teams/${currentTeamId}/events`).catch(() => ({}));
    if (teamTab !== 'home') return; // user moved on while we were loading

    const now = Date.now();
    const team = teamData.team;
    const members = teamData.members || [];
    const events = eventsData.events || [];

    // --- Next spawns: spawned first, then soonest ---
    const bosses = [...teamBosses]
        .map(b => ({ ...b, remaining: b.next_spawn - now, spawned: b.status === 'spawned' || b.next_spawn <= now }))
        .sort((a, b) => (a.spawned === b.spawned ? a.remaining - b.remaining : (a.spawned ? -1 : 1)))
        .slice(0, 4);
    const spawnedCount = teamBosses.filter(b => b.status === 'spawned' || b.next_spawn <= now).length;

    let spawnRows = '';
    for (const b of bosses) {
        const alertMs = (b.alert_minutes || 5) * 60000;
        const chip = b.spawned ? '<span class="chip chip-danger">Spawned</span>'
            : b.remaining <= alertMs ? '<span class="chip chip-warn">Soon</span>' : '';
        const when = b.spawned ? 'SPAWNED' : formatTime(b.remaining);
        const cls = b.spawned ? 'boss-countdown spawned' : (b.remaining <= alertMs ? 'boss-countdown warning-text' : 'boss-countdown active');
        spawnRows += `
            <div class="home-row" data-boss-id="${b.id}">
                <div class="grow">
                    <div class="title">${escapeHtml(b.name)}</div>
                    <div class="sub">${b.spawned ? 'Log the kill when it is down' : 'at ' + new Date(b.next_spawn).toLocaleTimeString([], tzOpts({ hour: '2-digit', minute: '2-digit' }))}</div>
                </div>
                ${chip}
                <span class="when ${cls}">${when}</span>
            </div>`;
    }
    if (!spawnRows) spawnRows = '<div class="home-empty">No timers yet. Add your first boss in Timers.</div>';

    // --- Upcoming events ---
    const live = events.filter(e => e.event_time <= now && e.event_time + (e.duration_minutes || 60) * 60000 > now);
    const upcoming = events.filter(e => e.event_time > now).sort((a, b) => a.event_time - b.event_time);
    const shown = [...live, ...upcoming].slice(0, 4);

    let eventRows = '';
    for (const e of shown) {
        const isLive = e.event_time <= now;
        const d = new Date(e.event_time);
        const whenText = isLive ? 'Happening now'
            : d.toLocaleDateString([], tzOpts({ weekday: 'short', month: 'short', day: 'numeric' })) + ' · ' + d.toLocaleTimeString([], tzOpts({ hour: '2-digit', minute: '2-digit' }));
        const mine = e.my_rsvp === 'going' ? '<span class="chip chip-success">Going</span>'
            : e.my_rsvp === 'maybe' ? '<span class="chip chip-warn">Maybe</span>'
            : e.my_rsvp === 'not_going' ? '<span class="chip chip-muted">Out</span>' : '';
        eventRows += `
            <div class="home-row" style="cursor:pointer" onclick="openModule('events')">
                <div class="grow">
                    <div class="title">${escapeHtml(e.title)}</div>
                    <div class="sub">${whenText} · ${e.going_count || 0} going</div>
                </div>
                ${isLive ? '<span class="chip chip-danger">Live</span>' : mine}
            </div>`;
    }
    if (!eventRows) eventRows = '<div class="home-empty">Nothing scheduled. Plan the next raid in Events.</div>';

    // --- Roster ---
    const nowSec = Math.floor(now / 1000);
    const online = members.filter(m => m.last_seen && (nowSec - m.last_seen) < 300).length;
    const leader = members.find(m => m.role === 'leader');

    el.innerHTML = `
        <div class="home-grid">
            <div class="card home-card">
                <div class="home-card-head"><h4>Next spawns${spawnedCount ? ` · <span style="color:var(--danger)">${spawnedCount} up</span>` : ''}</h4><a onclick="openModule('timers')">All timers</a></div>
                ${spawnRows}
            </div>
            <div class="card home-card">
                <div class="home-card-head"><h4>Upcoming events</h4><a onclick="openModule('events')">All events</a></div>
                ${eventRows}
            </div>
            <div class="card home-card">
                <div class="home-card-head"><h4>Roster</h4><a onclick="openModule('roster')">View roster</a></div>
                <div class="stat-big">${online} <span style="font-size:0.9rem;font-weight:600;color:var(--text-muted)">online</span></div>
                <div class="stat-sub">${members.length} of ${team.max_members || '∞'} members${leader ? ' · led by ' + escapeHtml(leader.username) : ''}</div>
                <div class="quick-actions">
                    <button class="btn btn-sm btn-secondary" onclick="copyInvite('${team.invite_code}')">Copy invite code</button>
                </div>
            </div>
        </div>`;
}
