// Background loops: boss/event countdown ticks, periodic refreshes, activity heartbeat

setInterval(() => {
    if (!currentTeamId) return;
    for (const boss of teamBosses) {
        const remaining = boss.next_spawn - Date.now();
        const isSpawned = remaining <= 0 || boss.status === 'spawned';
        const alertMs = (boss.alert_minutes || 5) * 60000;

        // Desktop notifications (work even when not on timers tab)
        if (isSpawned) {
            sendDesktopNotif('Boss Spawned!', `${boss.name} is now available!`, `spawn-${boss.id}`);
        } else if (remaining > 0 && remaining <= alertMs) {
            const minLeft = Math.max(1, Math.round(remaining / 60000));
            sendDesktopNotif('Boss Spawning Soon', `${boss.name} spawns in ${minLeft} min`, `warn-${boss.id}`);
        }

        // Update UI (only if on timers tab)
        if (teamTab !== 'timers' && teamTab !== 'home') continue;
        const el = document.querySelector(`[data-boss-id="${boss.id}"] .boss-countdown`);
        if (!el) continue;
        if (isSpawned) {
            el.textContent = 'SPAWNED';
            el.className = 'boss-countdown spawned';
        } else {
            el.textContent = formatTime(remaining);
            el.className = remaining <= alertMs ? 'boss-countdown warning-text' : 'boss-countdown active';
        }
    }
}, 1000);

// Refresh boss data from server every 15 seconds
setInterval(async () => {
    if (!currentTeamId || teamTab !== 'timers') return;
    await loadTeamBosses(currentTeamId);
    // Only update boss list area, not the add form
    const bossList = document.getElementById('bossListArea');
    if (bossList) {
        const team = teamData.team;
        const canManage = team.my_role === 'leader' || team.my_role === 'officer';
        bossList.innerHTML = renderBossListOnly(canManage);
    }
}, 15000);

// Tick — update event countdowns every second
setInterval(() => {
    if (!currentTeamId || teamTab !== 'events') return;
    for (const e of teamEvents) {
        const el = document.querySelector(`[data-event-id="${e.id}"] .event-countdown`);
        if (!el) continue;
        const remaining = e.event_time - Date.now();
        const isLive = remaining <= 0 && remaining > -(e.duration_minutes || 60) * 60000;
        if (isLive) {
            el.innerHTML = '<span style="color:#ef4444;font-weight:600"> LIVE NOW</span>';
        } else if (remaining > 0) {
            el.textContent = ` (in ${formatTimeLong(remaining)})`;
        } else {
            el.textContent = '';
        }
    }
}, 1000);

// Refresh event data from server every 30 seconds
setInterval(async () => {
    if (!currentTeamId || teamTab !== 'events') return;
    const data = await api('GET', `/api/teams/${currentTeamId}/events`);
    teamEvents = data.events || [];
    const el = document.getElementById('eventsListArea');
    if (el) el.innerHTML = renderEventsListOnly();
}, 30000);

// Activity heartbeat every 5 minutes
setInterval(async () => {
    if (!currentTeamId) return;
    await api('POST', `/api/teams/${currentTeamId}/heartbeat`);
}, 300000);
