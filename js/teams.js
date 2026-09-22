// Team list, create/join modals, membership actions (role, kick, leave, delete)

function _teamModal(title, fieldsHtml, submitLabel, onSubmit) {
    const host = document.getElementById('deathModal');
    host.innerHTML = `<div class="modal-backdrop"><div class="card modal-card"><h2>${title}</h2>
        <form class="tform" id="teamForm">${fieldsHtml}
            <div class="tf-actions tf-wide"><button type="button" class="btn btn-secondary" data-close="1">Cancel</button><button type="submit" class="btn btn-primary">${submitLabel}</button></div>
        </form></div></div>`;
    const back = host.firstElementChild;
    back.addEventListener('click', (e) => { if (e.target === back || e.target.closest('[data-close]')) host.innerHTML = ''; });
    back.querySelector('#teamForm').addEventListener('submit', (e) => { e.preventDefault(); onSubmit(); });
    setTimeout(() => back.querySelector('input')?.focus(), 0);
}

function showCreateTeamModal() {
    _teamModal('New team', `
        <label class="tf-field tf-wide"><span>Team name</span><input type="text" id="teamName" maxlength="60" required placeholder="e.g. Shadow Guild"></label>
        <p class="tf-help tf-wide">You become the leader. Share the invite code from the team bar to bring people in.</p>`, 'Create team', createTeam);
}

function showJoinTeamModal() {
    _teamModal('Join a team', `
        <label class="tf-field tf-wide"><span>Invite code</span><input type="text" id="inviteCode" maxlength="12" required placeholder="e.g. AbCd1234" autocapitalize="off" autocomplete="off"></label>
        <p class="tf-help tf-wide">Ask your leader for the 8-character code shown in their team bar.</p>`, 'Join', joinTeam);
}

async function showTeamList() {
    currentTeamId = null;
    const content = document.getElementById('mainContent');
    content.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';

    const data = await api('GET', '/api/teams');
    const teams = data.teams || [];
    const actions = `<div class="teams-actions">
        <button class="btn btn-secondary" onclick="showJoinTeamModal()">Join with code</button>
        <button class="btn btn-primary" onclick="showCreateTeamModal()">+ New team</button>
    </div>`;

    let html = `<div class="teams-head"><h2>Your teams</h2>${teams.length ? actions : ''}</div>`;
    if (teams.length === 0) {
        html += `<div class="t-empty card">
            <div class="t-empty-title">No teams yet</div>
            <div class="t-empty-sub">Create one for your guild, or join with the invite code your leader shares.</div>
            ${actions}
        </div>`;
    } else {
        html += '<div class="trows">' + teams.map(t => {
            const initials = t.name.split(/\s+/).map(w => w[0]).join('').slice(0, 2).toUpperCase();
            const stats = [`${t.member_count} member${t.member_count !== 1 ? 's' : ''}`,
                `<span class="${t.online_count ? 't-ok' : ''}">${t.online_count || 0} online</span>`,
                t.upcoming_events_24h > 0 ? `<span class="t-warnish">${t.upcoming_events_24h} event${t.upcoming_events_24h !== 1 ? 's' : ''} today</span>` : ''].filter(Boolean).join(' · ');
            return `
            <article class="trow-team" onclick="openTeam('${t.id}')" role="button" tabindex="0" onkeydown="if(event.key==='Enter')openTeam('${t.id}')">
                ${t.team_icon ? `<img class="trow-icon" src="${escapeHtml(t.team_icon)}" alt="">` : `<span class="trow-icon trow-initials">${escapeHtml(initials)}</span>`}
                <div class="trow-body">
                    <div class="trow-top"><span class="trow-name">${escapeHtml(t.name)}</span><span class="team-role ${t.role}">${t.role}</span></div>
                    <div class="trow-meta">${t.description ? escapeHtml(t.description) + ' · ' : ''}${stats}</div>
                </div>
                <span class="trow-chev">&#8250;</span>
            </article>`;
        }).join('') + '</div>';
        if (!currentUser?.premium) html += '<p class="teams-note">Free plan includes one team you lead; joining others is unlimited. <a href="#" onclick="showUpgradeModal();return false">Premium</a> removes the limit.</p>';
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
        _invalidateForMutation('/api/teams');
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
