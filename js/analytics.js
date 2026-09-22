// Analytics tab + CSV export

// --- Premium: Analytics Tab ---

async function loadAndRenderAnalytics() {
    teamTab = 'analytics';
    renderTeamView();
    const el = document.getElementById('analyticsContent');
    if (!el) return;

    const [actData, warData, dkpData, attData] = await Promise.all([
        api('GET', `/api/teams/${currentTeamId}/analytics?type=activity`),
        api('GET', `/api/teams/${currentTeamId}/analytics?type=wars`),
        api('GET', `/api/teams/${currentTeamId}/analytics?type=dkp`),
        api('GET', `/api/teams/${currentTeamId}/analytics?type=attendance`),
    ]);

    let html = '';

    // Activity overview
    html += '<div class="card"><h3>Member Activity</h3>';
    const activity = actData.data || [];
    if (activity.length === 0) {
        html += '<div class="empty-state">No activity data</div>';
    } else {
        const now = Math.floor(Date.now() / 1000);
        const online = activity.filter(a => a.last_seen && now - a.last_seen < 300).length;
        const today = activity.filter(a => a.last_seen && now - a.last_seen < 86400).length;
        const week = activity.filter(a => a.last_seen && now - a.last_seen < 604800).length;
        html += `<div style="display:flex;gap:12px;margin-top:8px">
            <div class="stat-box"><div class="stat-number" style="color:#34d399">${online}</div><div class="stat-label">Online Now</div></div>
            <div class="stat-box"><div class="stat-number" style="color:var(--accent2)">${today}</div><div class="stat-label">Active Today</div></div>
            <div class="stat-box"><div class="stat-number" style="color:var(--accent)">${week}</div><div class="stat-label">Active This Week</div></div>
        </div>`;
    }
    html += '</div>';

    // War trends
    html += '<div class="card"><h3>War Trends</h3>';
    const wars = warData.data || [];
    if (wars.length === 0) {
        html += '<div class="empty-state">No war data</div>';
    } else {
        // Group by month
        const byMonth = {};
        for (const w of wars) {
            const d = new Date(w.war_date * 1000);
            const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
            if (!byMonth[key]) byMonth[key] = { wins: 0, losses: 0, draws: 0 };
            if (w.result === 'win') byMonth[key].wins++;
            else if (w.result === 'loss') byMonth[key].losses++;
            else byMonth[key].draws++;
        }
        for (const [month, s] of Object.entries(byMonth)) {
            const total = s.wins + s.losses + s.draws;
            const wr = total > 0 ? Math.round(s.wins / total * 100) : 0;
            const barW = Math.max(5, wr);
            html += `<div style="display:flex;align-items:center;gap:8px;margin-top:6px;font-size:0.85em">
                <span style="width:70px;color:var(--text-muted)">${month}</span>
                <div style="flex:1;background:var(--bg-input);border-radius:4px;height:20px;overflow:hidden">
                    <div style="width:${barW}%;background:linear-gradient(90deg,#34d399,#059669);height:100%;border-radius:4px;transition:width 0.3s"></div>
                </div>
                <span style="width:80px;text-align:right"><span style="color:#34d399">${s.wins}W</span>/<span style="color:#ef4444">${s.losses}L</span> ${wr}%</span>
            </div>`;
        }
    }
    html += '</div>';

    // DKP progression
    html += '<div class="card"><h3>' + ptsName() + ' Top Earners</h3>';
    const dkp = dkpData.data || [];
    if (dkp.length === 0) {
        html += '<div class="empty-state">No ' + ptsName() + ' data</div>';
    } else {
        const balances = {};
        for (const d of dkp) {
            if (!balances[d.username]) balances[d.username] = 0;
            balances[d.username] += d.amount;
        }
        const sorted = Object.entries(balances).sort((a, b) => b[1] - a[1]).slice(0, 10);
        const maxBal = Math.max(...sorted.map(s => Math.abs(s[1])), 1);
        for (const [name, bal] of sorted) {
            const barW = Math.max(5, Math.abs(bal) / maxBal * 100);
            html += `<div style="display:flex;align-items:center;gap:8px;margin-top:4px;font-size:0.85em">
                <span style="width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${name}</span>
                <div style="flex:1;background:var(--bg-input);border-radius:4px;height:16px;overflow:hidden">
                    <div style="width:${barW}%;background:${bal >= 0 ? '#34d399' : '#ef4444'};height:100%;border-radius:4px"></div>
                </div>
                <span style="width:60px;text-align:right;color:${bal >= 0 ? '#34d399' : '#ef4444'}">${bal}</span>
            </div>`;
        }
    }
    html += '</div>';

    // Attendance rates
    html += '<div class="card"><h3>Attendance Rates</h3>';
    const att = attData.data || [];
    if (att.length === 0) {
        html += '<div class="empty-state">No attendance data</div>';
    } else {
        for (const a of att) {
            const rate = a.total > 0 ? Math.round(a.attended / a.total * 100) : 0;
            const barW = Math.max(5, rate);
            html += `<div style="display:flex;align-items:center;gap:8px;margin-top:4px;font-size:0.85em">
                <span style="width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(a.username)}</span>
                <div style="flex:1;background:var(--bg-input);border-radius:4px;height:16px;overflow:hidden">
                    <div style="width:${barW}%;background:var(--accent);height:100%;border-radius:4px"></div>
                </div>
                <span style="width:70px;text-align:right;color:var(--text-muted)">${a.attended}/${a.total} (${rate}%)</span>
            </div>`;
        }
    }
    html += '</div>';

    // CSV Export
    html += `<div class="card"><h3>Export Data (CSV)</h3>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px">
            <button class="btn btn-secondary btn-sm" onclick="exportCSV('members')">Members</button>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV('dkp')">${ptsName()}</button>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV('wars')">Wars</button>
            <button class="btn btn-secondary btn-sm" onclick="exportCSV('loot')">Loot</button>
        </div>
    </div>`;

    el.innerHTML = html;
}

const exportCSV = guard('exportCSV', async function(type) {
    const resp = await fetch(`${API}/api/teams/${currentTeamId}/export?type=${type}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const csv = await resp.text();
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${type}-export.csv`; a.click();
    URL.revokeObjectURL(url);
    showToast(`${type} exported!`);
});
