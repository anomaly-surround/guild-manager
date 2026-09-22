// Team list, create/join modals, membership actions (role, kick, leave, delete)

function showCreateTeamModal() {
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:400px;max-width:90vw;margin:0;">
                <h2>Create Team</h2>
                <div class="form-group">
                    <label>Team Name</label>
                    <input type="text" id="teamName" placeholder="e.g. Shadow Guild">
                </div>
                <div style="display:flex;gap:8px;margin-top:12px;">
                    <button class="btn btn-primary" onclick="createTeam()">Create</button>
                    <button class="btn" style="background:var(--bg-input);color:var(--text);" onclick="document.getElementById('deathModal').innerHTML=''">Cancel</button>
                </div>
            </div>
        </div>`;
}

function showJoinTeamModal() {
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:400px;max-width:90vw;margin:0;">
                <h2>Join Team</h2>
                <div class="form-group">
                    <label>Invite Code</label>
                    <input type="text" id="inviteCode" placeholder="e.g. AbCd1234">
                </div>
                <div style="display:flex;gap:8px;margin-top:12px;">
                    <button class="btn btn-primary" onclick="joinTeam()">Join</button>
                    <button class="btn" style="background:var(--bg-input);color:var(--text);" onclick="document.getElementById('deathModal').innerHTML=''">Cancel</button>
                </div>
            </div>
        </div>`;
}

async function showTeamList() {
    currentTeamId = null;
    const content = document.getElementById('mainContent');
    content.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';

    const data = await api('GET', '/api/teams');
    const teams = data.teams || [];

    let html = `
        <h3 style="color:var(--text-muted);margin:20px 0 14px;font-size:1.1em">Your Teams</h3>
    `;

    if (teams.length === 0) {
        html += '<div class="empty-state">No teams yet. Create or join one above.</div>';
    } else {
        for (const t of teams) {
            const initials = t.name.split(' ').map(w => w[0]).join('').substring(0, 2).toUpperCase();
            html += `
                <div class="team-card" onclick="openTeam('${t.id}')">
                    ${t.team_icon ? `<img class="team-icon" src="${t.team_icon}" style="object-fit:cover">` : `<div class="team-icon">${initials}</div>`}
                    <div class="team-info">
                        <div class="team-name">${escapeHtml(t.name)}</div>
                        ${t.description ? `<div class="team-desc">${escapeHtml(t.description)}</div>` : ''}
                        <div class="team-stats">
                            <span>${t.member_count} member${t.member_count !== 1 ? 's' : ''}</span>
                            <span style="color:#34d399">${t.online_count || 0} online</span>
                            ${t.upcoming_events_24h > 0 ? `<span style="color:#f59e0b">${t.upcoming_events_24h} event${t.upcoming_events_24h !== 1 ? 's' : ''} today</span>` : ''}
                        </div>
                    </div>
                    <div class="team-card-right">
                        <span class="team-role ${t.role}">${t.role}</span>
                    </div>
                </div>
            `;
        }
    }

    content.innerHTML = html;
}

const createTeam = guard('createTeam', async function() {
    const name = document.getElementById('teamName').value.trim();
    if (!name) return;
    const data = await api('POST', '/api/teams', { name });
    if (data.error) { showToast(data.error); document.getElementById('deathModal').innerHTML = ''; return; }
    document.getElementById('deathModal').innerHTML = '';
    showToast(`Team "${name}" created!`);
    showTeamList();
});

const joinTeam = guard('joinTeam', async function() {
    const code = document.getElementById('inviteCode').value.trim();
    if (!code) return;
    const data = await api('POST', `/api/invite/${code}`);
    if (data.error) { showToast(data.error); document.getElementById('deathModal').innerHTML = ''; return; }
    document.getElementById('deathModal').innerHTML = '';
    if (data.pending) {
        showToast('Join request sent! Waiting for approval.');
    } else {
        showToast(`Joined ${data.team.name}!`);
        showTeamList();
    }
});

const deleteTeam = guard('deleteTeam', async function(teamId) {
    if (!confirm('Delete this team? This cannot be undone.')) return;
    await api('DELETE', `/api/teams/${teamId}`);
    showToast('Team deleted');
    showTeamList();
});

const leaveTeam = guard('leaveTeam', async function(teamId) {
    if (!confirm('Leave this team?')) return;
    await api('POST', `/api/teams/${teamId}/leave`);
    showToast('Left team');
    showTeamList();
});
