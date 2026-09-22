// Match scheduling tab (challenges between teams)

// --- Match Scheduling ---

let matchSearchTimeout = null;

async function loadAndRenderMatches() {
    teamTab = 'matches';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/matches`);
    const el = document.getElementById('matchesContent');
    if (el) el.innerHTML = renderMatchesContent(data.matches || []);
}

function renderMatchesContent(matches) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    const myTeamId = currentTeamId;
    let html = '';

    // Challenge form
    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('challengeForm', this)">
                    <h3>+ Send Challenge</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="challengeForm">
                    <div class="form-group" style="margin-top:12px">
                        <label>Search Team</label>
                        <input type="text" id="matchTeamSearch" placeholder="Type a team name..." oninput="searchTeamsForMatch(this.value)" autocomplete="off">
                        <div id="matchTeamResults" style="margin-top:4px"></div>
                        <input type="hidden" id="matchOpponentId">
                        <div id="matchSelectedTeam" style="margin-top:4px;font-size:0.85em;color:var(--accent);font-weight:600"></div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Match Type</label>
                            <select id="matchType" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                                <option value="gvg">GvG</option>
                                <option value="scrim">Scrim</option>
                                <option value="raid">Raid</option>
                                <option value="other">Other</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Scheduled Time (optional)</label>
                            <input type="datetime-local" id="matchTime" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Message (optional)</label>
                        <input type="text" id="matchMessage" placeholder="e.g. Best of 3, no items" maxlength="200">
                    </div>
                    <div><button class="btn btn-primary" onclick="sendChallenge()">Send Challenge</button></div>
                </div>
            </div>
        `;
    }

    // Incoming challenges
    const incoming = matches.filter(m => m.challenged_team_id === myTeamId && m.status === 'pending');
    if (incoming.length > 0) {
        html += '<div class="card"><h3 style="color:#f59e0b">Incoming Challenges (' + incoming.length + ')</h3>';
        for (const m of incoming) {
            const time = m.scheduled_time ? new Date(m.scheduled_time).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'TBD';
            html += `<div style="padding:10px;background:var(--bg-item);border-radius:8px;margin-bottom:8px;border-left:3px solid #f59e0b">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <div>
                        <span style="font-weight:700">${escapeHtml(m.challenger_name)}</span>
                        <span class="event-type-badge ${m.match_type}" style="margin-left:4px">${m.match_type}</span>
                        <div style="font-size:0.8em;color:var(--text-muted);margin-top:2px">Scheduled: ${time}</div>
                        ${m.message ? `<div style="font-size:0.85em;color:var(--text-muted);margin-top:2px;font-style:italic">"${escapeHtml(m.message)}"</div>` : ''}
                    </div>
                    ${canManage ? `<div style="display:flex;gap:4px">
                        <button class="btn btn-sm" style="background:#065f46;color:#34d399;padding:4px 12px" onclick="respondMatch('${m.id}','accept')">Accept</button>
                        <button class="btn btn-sm" style="background:#7f1d1d;color:#ef4444;padding:4px 12px" onclick="respondMatch('${m.id}','decline')">Decline</button>
                    </div>` : ''}
                </div>
            </div>`;
        }
        html += '</div>';
    }

    // Accepted / upcoming matches
    const accepted = matches.filter(m => m.status === 'accepted');
    if (accepted.length > 0) {
        html += '<div class="card"><h3 style="color:#34d399">Upcoming Matches (' + accepted.length + ')</h3>';
        for (const m of accepted) {
            const opponent = m.challenger_team_id === myTeamId ? m.challenged_name : m.challenger_name;
            const time = m.scheduled_time ? new Date(m.scheduled_time).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'TBD';
            html += `<div style="padding:10px;background:var(--bg-item);border-radius:8px;margin-bottom:8px;border-left:3px solid #34d399">
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <div>
                        <span style="font-weight:700">vs ${escapeHtml(opponent)}</span>
                        <span class="event-type-badge ${m.match_type}" style="margin-left:4px">${m.match_type}</span>
                        <div style="font-size:0.8em;color:var(--text-muted);margin-top:2px">${time}</div>
                    </div>
                    ${canManage ? `<div style="display:flex;gap:4px">
                        <button class="btn btn-secondary btn-sm" onclick="showResultModal('${m.id}','${escapeHtml(m.challenger_name)}','${escapeHtml(m.challenged_name)}')">Log Result</button>
                        <button class="btn btn-danger btn-sm" onclick="deleteMatch('${m.id}')">X</button>
                    </div>` : ''}
                </div>
            </div>`;
        }
        html += '</div>';
    }

    // Outgoing pending
    const outgoing = matches.filter(m => m.challenger_team_id === myTeamId && m.status === 'pending');
    if (outgoing.length > 0) {
        html += '<div class="card"><h3>Pending Sent (' + outgoing.length + ')</h3>';
        for (const m of outgoing) {
            const time = m.scheduled_time ? new Date(m.scheduled_time).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'TBD';
            html += `<div class="dkp-row" style="padding:8px 0">
                <div>
                    <span style="font-weight:600">vs ${escapeHtml(m.challenged_name)}</span>
                    <span class="event-type-badge ${m.match_type}" style="margin-left:4px">${m.match_type}</span>
                    <div style="font-size:0.75em;color:var(--text-dim)">${time} &middot; Waiting for response</div>
                </div>
                ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteMatch('${m.id}')" style="font-size:0.7em">Cancel</button>` : ''}
            </div>`;
        }
        html += '</div>';
    }

    // Completed / declined
    const past = matches.filter(m => m.status === 'completed' || m.status === 'declined');
    if (past.length > 0) {
        html += '<div class="card"><h3>Match History</h3>';
        for (const m of past) {
            const opponent = m.challenger_team_id === myTeamId ? m.challenged_name : m.challenger_name;
            const date = new Date(m.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });

            if (m.status === 'declined') {
                html += `<div class="dkp-row" style="padding:6px 0">
                    <span>vs ${escapeHtml(opponent)} <span class="event-type-badge ${m.match_type}">${m.match_type}</span></span>
                    <span style="color:#ef4444;font-size:0.85em">DECLINED &middot; ${date}</span>
                </div>`;
            } else {
                const isWinner = m.winner_team_id === myTeamId;
                const isDraw = m.winner_team_id === null && m.result_challenger !== null;
                const resultColor = isWinner ? '#34d399' : isDraw ? '#f59e0b' : '#ef4444';
                const resultText = isWinner ? 'WIN' : isDraw ? 'DRAW' : 'LOSS';
                const score = m.result_challenger !== null ? `${m.result_challenger}-${m.result_challenged}` : '';

                html += `<div class="dkp-row" style="padding:6px 0">
                    <span>vs ${escapeHtml(opponent)} ${score ? `<span style="color:var(--text-muted);font-size:0.85em">(${score})</span>` : ''} <span class="event-type-badge ${m.match_type}">${m.match_type}</span></span>
                    <span style="color:${resultColor};font-weight:700;font-size:0.85em">${resultText} &middot; ${date}</span>
                </div>`;
            }
        }
        html += '</div>';
    }

    if (matches.length === 0) {
        html += '<div class="card"><div class="empty-state">No matches yet — challenge another team!</div></div>';
    }

    return html;
}

function searchTeamsForMatch(query) {
    clearTimeout(matchSearchTimeout);
    if (query.length < 2) { document.getElementById('matchTeamResults').innerHTML = ''; return; }
    matchSearchTimeout = setTimeout(async () => {
        const data = await api('GET', `/api/teams/${currentTeamId}/search-teams?q=${encodeURIComponent(query)}`);
        const el = document.getElementById('matchTeamResults');
        if (!el) return;
        if (!data.teams || data.teams.length === 0) {
            el.innerHTML = '<div style="font-size:0.8em;color:var(--text-dim);padding:4px">No teams found</div>';
            return;
        }
        el.innerHTML = data.teams.map(t =>
            `<div style="padding:6px 10px;background:var(--bg-item);border-radius:6px;margin-bottom:2px;cursor:pointer;font-size:0.9em" onclick="selectMatchOpponent('${t.id}','${escapeHtml(t.name)}')">${escapeHtml(t.name)}</div>`
        ).join('');
    }, 300);
}

function selectMatchOpponent(teamId, name) {
    document.getElementById('matchOpponentId').value = teamId;
    document.getElementById('matchSelectedTeam').textContent = 'Selected: ' + name;
    document.getElementById('matchTeamResults').innerHTML = '';
    document.getElementById('matchTeamSearch').value = name;
}

const sendChallenge = guard('sendChallenge', async function() {
    const opponentId = document.getElementById('matchOpponentId').value;
    if (!opponentId) return showToast('Search and select a team first');

    const timeInput = document.getElementById('matchTime').value;
    const data = await api('POST', `/api/teams/${currentTeamId}/matches`, {
        opponentTeamId: opponentId,
        matchType: document.getElementById('matchType').value,
        scheduledTime: timeInput ? new Date(timeInput).getTime() : null,
        message: document.getElementById('matchMessage').value.trim(),
    });
    if (data.error) { showToast(data.error); return; }
    showToast('Challenge sent!');
    loadAndRenderMatches();
});

const respondMatch = guard('respondMatch', async function(matchId, action) {
    await api('POST', `/api/teams/${currentTeamId}/matches/${matchId}/${action}`);
    showToast(action === 'accept' ? 'Challenge accepted!' : 'Challenge declined');
    loadAndRenderMatches();
});

function showResultModal(matchId, challengerName, challengedName) {
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:400px;max-width:90vw;margin:0">
                <h2>Log Match Result</h2>
                <div class="form-row" style="margin-top:12px">
                    <div class="form-group">
                        <label>${escapeHtml(challengerName)}</label>
                        <input type="number" id="resultChallenger" min="0" placeholder="Score">
                    </div>
                    <div class="form-group">
                        <label>${escapeHtml(challengedName)}</label>
                        <input type="number" id="resultChallenged" min="0" placeholder="Score">
                    </div>
                </div>
                <div style="display:flex;gap:8px;margin-top:12px">
                    <button class="btn btn-primary" onclick="submitMatchResult('${matchId}')">Submit</button>
                    <button class="btn" style="background:var(--bg-input);color:var(--text)" onclick="document.getElementById('deathModal').innerHTML=''">Cancel</button>
                </div>
            </div>
        </div>`;
}

const submitMatchResult = guard('submitMatchResult', async function(matchId) {
    const sc = document.getElementById('resultChallenger').value;
    const sd = document.getElementById('resultChallenged').value;
    if (sc === '' || sd === '') return showToast('Enter both scores');
    const data = await api('POST', `/api/teams/${currentTeamId}/matches/${matchId}/result`, {
        scoreChallenger: parseInt(sc), scoreChallenged: parseInt(sd),
    });
    if (data.error) { showToast(data.error); return; }
    document.getElementById('deathModal').innerHTML = '';
    showToast('Result logged!');
    loadAndRenderMatches();
});

const deleteMatch = guard('deleteMatch', async function(matchId) {
    await api('DELETE', `/api/teams/${currentTeamId}/matches/${matchId}`);
    loadAndRenderMatches();
});
