// War log & stats tab

// --- Wars & Stats ---

async function loadAndRenderWars() {
    teamTab = 'wars';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/wars`);
    const el = document.getElementById('warsContent');
    if (el) el.innerHTML = renderWarsContent(data.wars || [], data.stats || {});
}

function renderWarsContent(wars, stats) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    const total = stats.wins + stats.losses + stats.draws;
    const winRate = total > 0 ? Math.round((stats.wins / total) * 100) : 0;
    let html = '';

    // Stats overview
    html += `
        <div style="display:flex;gap:8px;margin-bottom:16px">
            <div class="stat-box">
                <div class="stat-number" style="color:#34d399">${stats.wins || 0}</div>
                <div class="stat-label">Wins</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color:#ef4444">${stats.losses || 0}</div>
                <div class="stat-label">Losses</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color:#f59e0b">${stats.draws || 0}</div>
                <div class="stat-label">Draws</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color:#a78bfa">${winRate}%</div>
                <div class="stat-label">Win Rate</div>
            </div>
        </div>
    `;

    // Rival breakdown
    if (stats.byOpponent && Object.keys(stats.byOpponent).length > 0) {
        html += '<div class="card"><h3>Rivals</h3>';
        const rivals = Object.entries(stats.byOpponent).sort((a, b) => (b[1].wins + b[1].losses + b[1].draws) - (a[1].wins + a[1].losses + a[1].draws));
        for (const [opp, s] of rivals) {
            html += `
                <div class="dkp-row">
                    <span style="font-weight:600">${opp}</span>
                    <span style="font-size:0.85em">
                        <span style="color:#34d399">${s.wins}W</span> /
                        <span style="color:#ef4444">${s.losses}L</span> /
                        <span style="color:#f59e0b">${s.draws}D</span>
                    </span>
                </div>
            `;
        }
        html += '</div>';
    }

    // Log form
    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addWarForm', this)">
                    <h3>+ Log War Result</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addWarForm">
                    <div class="form-row" style="margin-top:12px">
                        <div class="form-group">
                            <label>Opponent</label>
                            <input type="text" id="warOpponent" placeholder="e.g. Shadow Legion">
                        </div>
                        <div class="form-group" style="max-width:120px">
                            <label>Result</label>
                            <select id="warResult" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                <option value="win">Win</option>
                                <option value="loss">Loss</option>
                                <option value="draw">Draw</option>
                            </select>
                        </div>
                        <div class="form-group" style="max-width:120px">
                            <label>Type</label>
                            <select id="warType" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                <option value="gvg">GvG</option>
                                <option value="scrim">Scrim</option>
                                <option value="raid">Raid</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row" style="margin-top:8px">
                        <div class="form-group" style="max-width:80px">
                            <label>Our Score</label>
                            <input type="number" id="warScoreUs" min="0">
                        </div>
                        <div class="form-group" style="max-width:80px">
                            <label>Their Score</label>
                            <input type="number" id="warScoreThem" min="0">
                        </div>
                        <div class="form-group">
                            <label>Notes (optional)</label>
                            <input type="text" id="warNotes" placeholder="e.g. Close fight, MVP: player">
                        </div>
                    </div>
                    <div style="margin-top:10px">
                        <button class="btn btn-primary" onclick="addWar()">Log Result</button>
                    </div>
                </div>
            </div>
        `;
    }

    // War history
    html += '<div class="card"><h3>War History</h3>';
    if (wars.length === 0) {
        html += '<div class="empty-state">No wars logged yet</div>';
    } else {
        for (const w of wars) {
            const date = new Date(w.war_date * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
            const score = w.score_us !== null && w.score_them !== null ? `${w.score_us}-${w.score_them}` : '';
            html += `
                <div class="war-item ${w.result}">
                    <div>
                        <span style="font-weight:600">vs ${escapeHtml(w.opponent)}</span>
                        ${score ? `<span style="font-size:0.85em;color:#94a3b8"> (${score})</span>` : ''}
                        <span class="event-type-badge ${w.event_type}" style="margin-left:4px">${w.event_type}</span>
                        ${w.notes ? `<div style="font-size:0.8em;color:#64748b;margin-top:2px">${escapeHtml(w.notes)}</div>` : ''}
                        <div style="font-size:0.7em;color:#64748b">${date} &middot; by ${escapeHtml(w.logged_by_name)}</div>
                    </div>
                    <div style="display:flex;align-items:center;gap:6px">
                        <span class="war-result ${w.result}">${w.result.toUpperCase()}</span>
                        ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteWar('${w.id}')" style="font-size:0.7em;padding:2px 8px">X</button>` : ''}
                    </div>
                </div>
            `;
        }
    }
    html += '</div>';

    return html;
}

const addWar = guard('addWar', async function() {
    const opponent = document.getElementById('warOpponent').value.trim();
    const result = document.getElementById('warResult').value;
    if (!opponent) return showToast('Opponent required');

    const scoreUs = document.getElementById('warScoreUs').value;
    const scoreThem = document.getElementById('warScoreThem').value;

    const data = await api('POST', `/api/teams/${currentTeamId}/wars`, {
        opponent, result,
        eventType: document.getElementById('warType').value,
        scoreUs: scoreUs !== '' ? parseInt(scoreUs) : undefined,
        scoreThem: scoreThem !== '' ? parseInt(scoreThem) : undefined,
        notes: document.getElementById('warNotes').value.trim() || null,
    });
    if (data.error) { showToast(data.error); return; }
    showToast('War result logged!');
    loadAndRenderWars();
});

const deleteWar = guard('deleteWar', async function(id) {
    await api('DELETE', `/api/teams/${currentTeamId}/wars/${id}`);
    loadAndRenderWars();
});
