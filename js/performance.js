// Performance tracker tab

// --- Performance Tracker ---

async function loadAndRenderPerformance() {
    teamTab = 'performance';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/performance`);
    const el = document.getElementById('performanceContent');
    if (el) el.innerHTML = renderPerformanceContent(data.entries || [], data.memberStats || {});
}

function renderPerformanceContent(entries, memberStats) {
    const team = teamData.team;
    const members = teamData.members;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    let html = '';

    // Member averages overview
    const statKeys = new Set();
    for (const uid in memberStats) {
        for (const s in memberStats[uid].stats) statKeys.add(s);
    }

    if (Object.keys(memberStats).length > 0 && statKeys.size > 0) {
        html += '<div class="card"><h3>Member Averages</h3><div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:0.85em">';
        html += '<tr style="border-bottom:1px solid var(--border)"><th style="text-align:left;padding:6px">Player</th>';
        for (const key of statKeys) html += `<th style="text-align:right;padding:6px">${escapeHtml(key)}</th>`;
        html += '</tr>';

        for (const uid in memberStats) {
            const m = memberStats[uid];
            html += `<tr style="border-bottom:1px solid var(--border)"><td style="padding:6px;font-weight:600">${escapeHtml(m.username)}</td>`;
            for (const key of statKeys) {
                const s = m.stats[key];
                const avg = s ? (s.total / s.count).toFixed(1) : '—';
                html += `<td style="text-align:right;padding:6px">${avg}</td>`;
            }
            html += '</tr>';
        }
        html += '</table></div></div>';
    }

    // Log form
    if (canManage) {
        const memberOpts = members.map(m => `<option value="${m.user_id}">${escapeHtml(m.username)}</option>`).join('');
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addPerfForm', this)">
                    <h3>+ Log Stats</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addPerfForm">
                    <div class="form-row" style="margin-top:12px">
                        <div class="form-group">
                            <label>Player</label>
                            <select id="perfMember" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                                ${memberOpts}
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Event / Match</label>
                            <input type="text" id="perfEventLabel" placeholder="e.g. GvG vs Shadow Legion" maxlength="100">
                        </div>
                    </div>
                    <div id="perfStatsContainer">
                        <label>Stats</label>
                        <div class="perf-stat-row" style="display:flex;gap:8px;margin-bottom:6px">
                            <input type="text" class="perf-stat-name" placeholder="Stat name (e.g. Kills)" style="flex:1" maxlength="50">
                            <input type="number" class="perf-stat-value" placeholder="Value" style="flex:1">
                        </div>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="addPerfStatField()" style="margin:8px 0">+ Add Stat</button>
                    <div><button class="btn btn-primary" onclick="logPerformance()">Log Stats</button></div>
                </div>
            </div>
        `;
    }

    // Recent entries
    html += '<div class="card"><h3>Recent Entries</h3>';
    if (entries.length === 0) {
        html += '<div class="empty-state">No stats logged yet</div>';
    } else {
        let lastLabel = '';
        for (const e of entries) {
            const label = `${e.player_name} — ${e.event_label}`;
            if (label !== lastLabel) {
                if (lastLabel) html += '</div>';
                const date = new Date(e.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                html += `<div style="margin-top:10px;padding:8px;background:var(--bg-item);border-radius:8px">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <span style="font-weight:600;font-size:0.9em">${escapeHtml(e.player_name)} — ${escapeHtml(e.event_label)}</span>
                        <span style="font-size:0.7em;color:var(--text-dim)">${date}</span>
                    </div>`;
                lastLabel = label;
            }
            html += `<div class="dkp-row" style="padding:2px 0">
                <span style="color:var(--text-muted);font-size:0.85em">${escapeHtml(e.stat_name)}</span>
                <span style="font-weight:600">${e.stat_value}</span>
            </div>`;
        }
        if (lastLabel) html += '</div>';
    }
    html += '</div>';
    return html;
}

function addPerfStatField() {
    const container = document.getElementById('perfStatsContainer');
    const count = container.querySelectorAll('.perf-stat-row').length;
    if (count >= 20) return showToast('Max 20 stats');
    const div = document.createElement('div');
    div.className = 'perf-stat-row';
    div.style.cssText = 'display:flex;gap:8px;margin-bottom:6px';
    div.innerHTML = `
        <input type="text" class="perf-stat-name" placeholder="Stat name" style="flex:1" maxlength="50">
        <input type="number" class="perf-stat-value" placeholder="Value" style="flex:1">`;
    container.appendChild(div);
}

const logPerformance = guard('logPerformance', async function() {
    const userId = document.getElementById('perfMember').value;
    const eventLabel = document.getElementById('perfEventLabel').value.trim();
    if (!eventLabel) return showToast('Event/match label required');

    const names = document.querySelectorAll('.perf-stat-name');
    const values = document.querySelectorAll('.perf-stat-value');
    const stats = [];
    names.forEach((n, i) => {
        if (n.value.trim() && values[i]?.value !== '') stats.push({ name: n.value.trim(), value: Number(values[i].value) });
    });
    if (stats.length === 0) return showToast('At least 1 stat required');

    const data = await api('POST', `/api/teams/${currentTeamId}/performance`, { userId, eventLabel, stats });
    if (data.error) { showToast(data.error); return; }
    showToast('Stats logged!');
    loadAndRenderPerformance();
});
