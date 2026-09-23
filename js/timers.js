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

        // Update Home rows (the Timers module runs its own tick)
        if (teamTab !== 'home') continue;
        const el = document.querySelector(`[data-boss-id="${boss.id}"] .boss-countdown`);
        if (!el) continue;
        if (isSpawned) {
            el.textContent = 'SPAWNED';
            el.className = 'when boss-countdown spawned';   // keep 'when': it carries the Home font size
        } else {
            el.textContent = formatTime(remaining);
            el.className = remaining <= alertMs ? 'when boss-countdown warning-text' : 'when boss-countdown active';
        }
    }
}, 1000);

// Activity heartbeat every 5 minutes
setInterval(async () => {
    if (!currentTeamId) return;
    await api('POST', `/api/teams/${currentTeamId}/heartbeat`);
}, 300000);
