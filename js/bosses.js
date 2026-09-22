// Boss timers tab: list/grid rendering, add/kill/delete, import/export, history, templates

function renderTimersTab(team, canManage) {
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    let html = `
        <div class="card">
            <div class="collapsible-header" onclick="toggleSection('addBossForm', this)">
                <h3>+ Add Boss</h3>
                <span class="toggle-arrow">&#9660;</span>
            </div>
            <div class="collapsible-body" id="addBossForm">
                <div class="form-row" style="margin-top:12px">
                    <div class="form-group">
                        <label>Boss Name</label>
                        <input type="text" id="bossName" placeholder="e.g. Dragon Lord">
                    </div>
                    <div class="form-group" style="max-width:160px">
                        <label>Type</label>
                        <select id="bossType" onchange="toggleBossInputs()" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                            <option value="interval">Interval</option>
                            <option value="fixed">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="twicedaily">Twice Daily</option>
                            <option value="biweekly">Twice a Week</option>
                        </select>
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px" id="bossIntervalRow">
                    <div class="form-group" style="max-width:80px">
                        <label>Hours</label>
                        <input type="number" id="bossHours" min="0" placeholder="H">
                    </div>
                    <div class="form-group" style="max-width:80px">
                        <label>Minutes</label>
                        <input type="number" id="bossMinutes" min="0" max="59" placeholder="M">
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px;display:none" id="bossFixedRow">
                    <div class="form-group" style="max-width:150px">
                        <label>Time</label>
                        <input type="time" id="bossFixedTime">
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px;display:none" id="bossWeeklyRow">
                    <div class="form-group" style="max-width:120px">
                        <label>Day</label>
                        <select id="bossWeeklyDay" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                            <option value="0">Sunday</option><option value="1">Monday</option><option value="2">Tuesday</option>
                            <option value="3">Wednesday</option><option value="4">Thursday</option><option value="5">Friday</option><option value="6">Saturday</option>
                        </select>
                    </div>
                    <div class="form-group" style="max-width:150px">
                        <label>Time</label>
                        <input type="time" id="bossWeeklyTime">
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px;display:none" id="bossTwiceDailyRow">
                    <div class="form-group" style="max-width:150px">
                        <label>Time 1</label>
                        <input type="time" id="bossTwiceTime1">
                    </div>
                    <div class="form-group" style="max-width:150px">
                        <label>Time 2</label>
                        <input type="time" id="bossTwiceTime2">
                    </div>
                </div>
                <div style="margin-top:8px;display:none" id="bossBiweeklyRow">
                    <div class="form-row">
                        <div class="form-group" style="max-width:120px">
                            <label>Day 1</label>
                            <select id="bossBiDay1" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                <option value="0">Sun</option><option value="1">Mon</option><option value="2">Tue</option>
                                <option value="3">Wed</option><option value="4">Thu</option><option value="5">Fri</option><option value="6">Sat</option>
                            </select>
                        </div>
                        <div class="form-group" style="max-width:150px">
                            <label>Time 1</label>
                            <input type="time" id="bossBiTime1">
                        </div>
                    </div>
                    <div class="form-row" style="margin-top:6px">
                        <div class="form-group" style="max-width:120px">
                            <label>Day 2</label>
                            <select id="bossBiDay2" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                <option value="0">Sun</option><option value="1">Mon</option><option value="2">Tue</option>
                                <option value="3">Wed</option><option value="4">Thu</option><option value="5">Fri</option><option value="6">Sat</option>
                            </select>
                        </div>
                        <div class="form-group" style="max-width:150px">
                            <label>Time 2</label>
                            <input type="time" id="bossBiTime2">
                        </div>
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px">
                    <div class="form-group" style="max-width:100px">
                        <label>Alert (min)</label>
                        <input type="number" id="bossAlert" value="5" min="1" max="60">
                    </div>
                    <div class="form-group" style="max-width:120px">
                        <label>Auto-reset (min)</label>
                        <input type="number" id="bossAutoReset" value="5" min="1" max="60">
                    </div>
                    <div><button class="btn btn-primary" onclick="addBoss()">Add Boss</button></div>
                </div>
            </div>
        </div>
    `;

    html += `<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
        <div class="view-toggle">
            <button class="${bossViewMode === 'list' ? 'active' : ''}" onclick="setBossView('list')">List</button>
            <button class="${bossViewMode === 'grid' ? 'active' : ''}" onclick="setBossView('grid')">Grid</button>
        </div>`;
    html += `<button class="btn btn-secondary btn-sm" onclick="exportBossTimers()">Export</button>`;
    if (canManage) html += `<button class="btn btn-secondary btn-sm" onclick="document.getElementById('bossImportFile').click()">Import</button>
        <input type="file" id="bossImportFile" accept=".json" style="display:none" onchange="importBossTimers(event)">
        <button class="btn btn-sm" style="background:#3b1111;color:#f87171;border:1px solid #7f1d1d44" onclick="removeAllBosses()">Remove All</button>`;
    if (teamData?.team?.premium_team) {
        html += `
            <button class="btn btn-secondary btn-sm" onclick="showBossHistory()">Kill History</button>
            <button class="btn btn-secondary btn-sm" onclick="showBossTemplates()">Templates</button>`;
    }
    html += `<input type="text" id="bossSearch" placeholder="Search bosses..." oninput="filterBossList()" style="background:var(--card-bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:0.85em;width:160px;margin-left:auto">`;
    html += '</div>';
    html += '<div id="bossListArea" class="' + (bossViewMode === 'grid' ? 'boss-grid' : '') + '">' + renderBossListOnly(canManage) + '</div>';
    return html;
}

function filterBossList() {
    const area = document.getElementById('bossListArea');
    if (!area) return;
    const canManage = teamData?.member?.role === 'leader' || teamData?.member?.role === 'officer';
    area.innerHTML = renderBossListOnly(canManage);
}

function renderBossListOnly(canManage) {
    if (teamBosses.length === 0) {
        return '<div class="empty-state">No boss timers yet</div>';
    }
    const search = (document.getElementById('bossSearch')?.value || '').toLowerCase();
    const filtered = search ? teamBosses.filter(b => b.name.toLowerCase().includes(search)) : teamBosses;
    if (filtered.length === 0) {
        return '<div class="empty-state">No bosses match your search</div>';
    }
    const fullDayNames = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    let html = '';
    const sorted = [...filtered].sort((a, b) => {
        if (a.status === 'spawned' && b.status !== 'spawned') return -1;
        if (b.status === 'spawned' && a.status !== 'spawned') return 1;
        return a.next_spawn - b.next_spawn;
    });

    for (const boss of sorted) {
        const now = Date.now();
        const remaining = boss.next_spawn - now;
        const alertMs = boss.alert_minutes * 60000;
        const isSpawned = remaining <= 0 || boss.status === 'spawned';
        const isWarning = !isSpawned && remaining <= alertMs;

        let cls = 'boss-item';
        if (isSpawned) cls += ' spawning';
        else if (isWarning) cls += ' warning';

        let countdownCls = 'boss-countdown active';
        let countdownText = formatTime(remaining);
        if (isSpawned) { countdownCls = 'boss-countdown spawned'; countdownText = 'SPAWNED'; }
        else if (isWarning) { countdownCls = 'boss-countdown warning-text'; }

        let meta = '';
        if (boss.type === 'interval') {
            const totalMin = boss.interval_ms / 60000;
            const h = Math.floor(totalMin / 60), m = totalMin % 60;
            meta = 'Every ' + (h > 0 ? h + 'h ' : '') + (m > 0 ? m + 'm' : '');
        } else if (boss.type === 'fixed') {
            meta = 'Daily at ' + boss.fixed_time;
        } else if (boss.type === 'weekly') {
            meta = fullDayNames[boss.weekly_day] + ' at ' + boss.weekly_time;
        } else if (boss.type === 'twicedaily') {
            try {
                const times = typeof boss.biweekly_days === 'string' ? JSON.parse(boss.biweekly_days) : boss.biweekly_days;
                meta = 'Daily at ' + times.join(' & ');
            } catch { meta = 'Twice daily'; }
        } else if (boss.type === 'biweekly') {
            try {
                const days = typeof boss.biweekly_days === 'string' ? JSON.parse(boss.biweekly_days) : boss.biweekly_days;
                meta = days.map(d => dayNames[d.day] + ' ' + d.time).join(' & ');
            } catch { meta = 'Twice a week'; }
        }

        html += `
            <div class="${cls}" data-boss-id="${boss.id}">
                <div style="flex:1">
                    <div class="boss-name-text">${escapeHtml(boss.name)}</div>
                    <div class="boss-meta-text">${meta} | Alert: ${boss.alert_minutes}m | Reset: ${boss.auto_reset_minutes || 5}m</div>
                    ${boss.last_death ? `<div class="boss-death-text">Killed: ${new Date(boss.last_death).toLocaleString()}</div>` : ''}
                </div>
                <div class="${countdownCls}">${countdownText}</div>
                <div class="boss-actions">
                    <button class="btn btn-sm" style="background:#065f46;color:#34d399" onclick="killBoss('${boss.id}')">Killed</button>
                    <button class="btn btn-sm" style="background:#1e3a5f;color:#60a5fa" onclick="openDeathModal('${boss.id}','${escapeHtml(boss.name)}')">Set Death</button>
                    ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteBoss('${boss.id}')">X</button>` : ''}
                </div>
            </div>
        `;
    }
    return html;
}

// --- Boss timer actions ---

function setBossView(mode) {
    bossViewMode = mode;
    localStorage.setItem('gm_boss_view', mode);
    renderTeamView();
}

function toggleBossInputs() {
    const type = document.getElementById('bossType').value;
    document.getElementById('bossIntervalRow').style.display = type === 'interval' ? '' : 'none';
    document.getElementById('bossFixedRow').style.display = type === 'fixed' ? '' : 'none';
    document.getElementById('bossWeeklyRow').style.display = type === 'weekly' ? '' : 'none';
    document.getElementById('bossTwiceDailyRow').style.display = type === 'twicedaily' ? '' : 'none';
    document.getElementById('bossBiweeklyRow').style.display = type === 'biweekly' ? '' : 'none';
}

function toggleSection(id, el) {
    document.getElementById(id).classList.toggle('open');
    el.querySelector('.toggle-arrow').classList.toggle('open');
}

const addBoss = guard('addBoss', async function() {
    const name = document.getElementById('bossName').value.trim();
    if (!name) return;
    const type = document.getElementById('bossType').value;
    const alertMinutes = parseInt(document.getElementById('bossAlert').value) || 5;
    const autoResetMinutes = parseInt(document.getElementById('bossAutoReset').value) || 5;

    const body = { name, type, alertMinutes, autoResetMinutes };

    if (type === 'interval') {
        const h = parseInt(document.getElementById('bossHours').value) || 0;
        const m = parseInt(document.getElementById('bossMinutes').value) || 0;
        if (h === 0 && m === 0) return;
        body.intervalMs = (h * 3600 + m * 60) * 1000;
    } else if (type === 'fixed') {
        body.fixedTime = document.getElementById('bossFixedTime').value;
        if (!body.fixedTime) return;
    } else if (type === 'weekly') {
        body.weeklyDay = parseInt(document.getElementById('bossWeeklyDay').value);
        body.weeklyTime = document.getElementById('bossWeeklyTime').value;
        if (!body.weeklyTime) return;
    } else if (type === 'twicedaily') {
        const t1 = document.getElementById('bossTwiceTime1').value;
        const t2 = document.getElementById('bossTwiceTime2').value;
        if (!t1 || !t2) return;
        body.twiceDailyTimes = [t1, t2];
    } else if (type === 'biweekly') {
        const time1 = document.getElementById('bossBiTime1').value;
        const time2 = document.getElementById('bossBiTime2').value;
        if (!time1 || !time2) return;
        body.biweeklyDays = [
            { day: parseInt(document.getElementById('bossBiDay1').value), time: time1 },
            { day: parseInt(document.getElementById('bossBiDay2').value), time: time2 },
        ];
    }

    const data = await api('POST', `/api/teams/${currentTeamId}/bosses`, body);
    if (data.error) { showToast(data.error); return; }
    showToast(`${name} added`);
    await loadTeamBosses(currentTeamId);
    renderTeamView();
});

const killBoss = guard('killBoss', async function(bossId) {
    await api('POST', `/api/teams/${currentTeamId}/bosses/${bossId}/kill`, { deathTime: Date.now() });
    await loadTeamBosses(currentTeamId);
    renderTeamView();
});

function openDeathModal(bossId, bossName) {
    const now = new Date();
    const defaultDate = now.toISOString().slice(0, 10);
    const defaultTime = now.toTimeString().slice(0, 5);
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:flex;align-items:center;justify-content:center;z-index:2000" onclick="closeDeathModal(event)">
            <div class="card" style="min-width:320px;margin:0" onclick="event.stopPropagation()">
                <h3 style="color:#a78bfa;margin-bottom:16px">Set Death Time: ${bossName}</h3>
                <div class="form-group" style="margin-bottom:12px">
                    <label>Date</label>
                    <input type="date" id="deathDate" value="${defaultDate}">
                </div>
                <div class="form-group" style="margin-bottom:16px">
                    <label>Time</label>
                    <input type="time" id="deathTime" value="${defaultTime}" step="60">
                </div>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button class="btn btn-secondary" onclick="closeDeathModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="confirmDeathTime('${bossId}')">Set Death Time</button>
                </div>
            </div>
        </div>
    `;
}

function closeDeathModal(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('deathModal').innerHTML = '';
}

async function confirmDeathTime(bossId) {
    const dateVal = document.getElementById('deathDate').value;
    const timeVal = document.getElementById('deathTime').value;
    if (!dateVal || !timeVal) return;
    const deathTime = new Date(`${dateVal}T${timeVal}`).getTime();
    if (isNaN(deathTime)) return;
    await api('POST', `/api/teams/${currentTeamId}/bosses/${bossId}/kill`, { deathTime });
    closeDeathModal();
    showToast('Death time updated');
    await loadTeamBosses(currentTeamId);
    renderTeamView();
}

const deleteBoss = guard('deleteBoss', async function(bossId) {
    if (!confirm('Remove this boss timer?')) return;
    await api('DELETE', `/api/teams/${currentTeamId}/bosses/${bossId}`);
    await loadTeamBosses(currentTeamId);
    renderTeamView();
});

function exportBossTimers() {
    if (teamBosses.length === 0) { showToast('No bosses to export'); return; }
    const exportData = {
        version: 1,
        exportedAt: Date.now(),
        bosses: teamBosses.map(b => {
            const entry = {
                name: b.name,
                type: b.type,
                alert_minutes: b.alert_minutes,
                auto_reset_minutes: b.auto_reset_minutes || 5,
                last_death: b.last_death || null,
            };
            if (b.type === 'interval') entry.interval_ms = b.interval_ms;
            if (b.type === 'fixed') entry.fixed_time = b.fixed_time;
            if (b.type === 'weekly') { entry.weekly_day = b.weekly_day; entry.weekly_time = b.weekly_time; }
            if (b.type === 'twicedaily') { try { entry.twice_daily_times = typeof b.biweekly_days === 'string' ? JSON.parse(b.biweekly_days) : b.biweekly_days; } catch { entry.twice_daily_times = []; } }
            if (b.type === 'biweekly') entry.biweekly_days = typeof b.biweekly_days === 'string' ? JSON.parse(b.biweekly_days) : b.biweekly_days;
            return entry;
        }),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `boss-timers-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${teamBosses.length} boss(es)`);
}

async function importBossTimers(event) {
    const file = event.target.files[0];
    if (!file) return;
    event.target.value = '';
    try {
        const text = await file.text();
        const data = JSON.parse(text);
        if (!data.bosses || !Array.isArray(data.bosses)) { showToast('Invalid file format'); return; }
        if (data.bosses.length === 0) { showToast('No bosses in file'); return; }

        const existing = teamBosses.map(b => b.name.toLowerCase());
        const dupes = data.bosses.filter(b => existing.includes(b.name.toLowerCase()));
        let msg = `Import ${data.bosses.length} boss(es)?`;
        if (dupes.length > 0) msg += `\n${dupes.length} already exist and will be skipped.`;
        if (!confirm(msg)) return;

        const validTypes = ['interval', 'fixed', 'weekly', 'twicedaily', 'biweekly'];
        let added = 0;
        for (const b of data.bosses) {
            if (!b.name || typeof b.name !== 'string' || !validTypes.includes(b.type)) continue;
            if (b.name.length > 100) continue;
            if (existing.includes(b.name.toLowerCase())) continue;

            const body = {
                name: b.name,
                type: b.type,
                alertMinutes: b.alert_minutes || 5,
                autoResetMinutes: b.auto_reset_minutes || 5,
            };
            if (b.type === 'interval') body.intervalMs = b.interval_ms;
            if (b.type === 'fixed') body.fixedTime = b.fixed_time;
            if (b.type === 'weekly') { body.weeklyDay = b.weekly_day; body.weeklyTime = b.weekly_time; }
            if (b.type === 'twicedaily') body.twiceDailyTimes = b.twice_daily_times;
            if (b.type === 'biweekly') body.biweeklyDays = b.biweekly_days;

            const result = await api('POST', `/api/teams/${currentTeamId}/bosses`, body);
            if (result && result.id && b.last_death) {
                await api('POST', `/api/teams/${currentTeamId}/bosses/${result.id}/kill`, { deathTime: b.last_death });
            }
            added++;
        }
        await loadTeamBosses(currentTeamId);
        renderTeamView();
        showToast(`Imported ${added} boss(es)${dupes.length ? `, skipped ${dupes.length} duplicate(s)` : ''}`);
    } catch (e) {
        showToast('Failed to import: ' + e.message);
    }
}

async function removeAllBosses() {
    if (teamBosses.length === 0) { showToast('No bosses to remove'); return; }
    if (!confirm(`Remove ALL ${teamBosses.length} boss timer(s)? This cannot be undone.`)) return;
    for (const b of [...teamBosses]) {
        await api('DELETE', `/api/teams/${currentTeamId}/bosses/${b.id}`);
    }
    await loadTeamBosses(currentTeamId);
    renderTeamView();
    showToast('All boss timers removed');
}

// --- Premium: Boss History Modal ---

const showBossHistory = guard('showBossHistory', async function() {
    const data = await api('GET', `/api/teams/${currentTeamId}/bosses/history`);
    let html = '<h2>Boss Kill History</h2>';
    const stats = data.stats || [];
    if (stats.length > 0) {
        html += '<h3 style="color:var(--text-muted);margin:12px 0 8px">Kill Stats</h3>';
        for (const s of stats) {
            html += `<div class="dkp-row"><span>${escapeHtml(s.boss_name)}</span><span style="color:#34d399">${s.kill_count} kills</span></div>`;
        }
    }
    const history = data.history || [];
    if (history.length > 0) {
        html += '<h3 style="color:var(--text-muted);margin:12px 0 8px">Recent Kills</h3>';
        for (const h of history.slice(0, 20)) {
            const date = new Date(h.killed_at).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
            html += `<div style="font-size:0.85em;padding:4px 0;border-bottom:1px solid var(--border)">${escapeHtml(h.boss_name)} <span style="color:var(--text-dim)">by ${escapeHtml(h.killed_by_name || 'unknown')} &middot; ${date}</span></div>`;
        }
    } else {
        html += '<div class="empty-state">No kills logged yet</div>';
    }
    html += '<button class="btn btn-secondary btn-sm" onclick="document.getElementById(\'deathModal\').innerHTML=\'\'" style="margin-top:12px">Close</button>';
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:500px;max-width:90vw;margin:0;max-height:80vh;overflow-y:auto">${html}</div>
        </div>`;
});

const showBossTemplates = guard('showBossTemplates', async function() {
    const data = await api('GET', '/api/boss-templates');
    const templates = data.templates || [];
    let html = '<h2>Boss Templates</h2>';
    if (templates.length === 0) {
        html += '<div class="empty-state">No templates available</div>';
    } else {
        for (const t of templates) {
            const bosses = JSON.parse(t.bosses);
            html += `<div class="dkp-row"><div><span style="font-weight:600">${escapeHtml(t.name)}</span> <span style="color:var(--text-dim);font-size:0.8em">(${t.game} &middot; ${bosses.length} bosses)</span></div>
                <button class="btn btn-primary btn-sm" onclick="importBossTemplate('${t.id}')" style="font-size:0.75em">Import</button></div>`;
        }
    }
    html += `<div style="margin-top:12px;display:flex;gap:8px">
        <button class="btn btn-secondary btn-sm" onclick="saveBossesAsTemplate()">Save Current as Template</button>
        <button class="btn btn-secondary btn-sm" onclick="document.getElementById('deathModal').innerHTML=''">Close</button>
    </div>`;
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:500px;max-width:90vw;margin:0;max-height:80vh;overflow-y:auto">${html}</div>
        </div>`;
});

const importBossTemplate = guard('importBossTemplate', async function(templateId) {
    const data = await api('POST', `/api/teams/${currentTeamId}/bosses/import-template`, { templateId });
    if (data.error) { showToast(data.error); return; }
    showToast(`Imported ${data.count} bosses!`);
    document.getElementById('deathModal').innerHTML = '';
    await loadTeamBosses(currentTeamId);
    renderTeamView();
});

const saveBossesAsTemplate = guard('saveBossesAsTemplate', async function() {
    const name = prompt('Template name:');
    if (!name) return;
    const game = prompt('Game name:');
    if (!game) return;
    const bosses = teamBosses.map(b => ({ name: b.name, type: b.type, intervalMs: b.interval_ms, fixedTime: b.fixed_time, weeklyDay: b.weekly_day, weeklyTime: b.weekly_time, biweeklyDays: b.biweekly_days ? JSON.parse(b.biweekly_days) : null, alertMinutes: b.alert_minutes }));
    await api('POST', '/api/boss-templates', { name, game, bosses });
    showToast('Template saved!');
});
