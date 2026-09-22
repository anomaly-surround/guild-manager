// Team view shell: state, openTeam(), tab rendering, mobile tab switcher

let teamBosses = [];
let teamData = null;
let teamTab = 'timers';
let bossViewMode = localStorage.getItem('gm_boss_view') || 'list';

async function openTeam(teamId) {
    currentTeamId = teamId;
    const content = document.getElementById('mainContent');
    content.innerHTML = '<div class="empty-state"><div class="spinner"></div></div>';

    const data = await api('GET', `/api/teams/${teamId}`);
    if (data.error) { showToast(data.error); showTeamList(); return; }

    teamData = data;
    teamTab = 'dashboard';
    // Load points name setting
    api('GET', `/api/teams/${teamId}/settings`).then(s => { _pointsName = s.pointsName || 'DKP'; }).catch(() => {});
    await loadTeamBosses(teamId);
    loadAndRenderDashboard();
}

async function loadTeamBosses(teamId) {
    const data = await api('GET', `/api/teams/${teamId}/bosses`);
    teamBosses = data.bosses || [];
}

function renderTeamView() {
    const content = document.getElementById('mainContent');
    const team = teamData.team;
    const members = teamData.members;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';

    let tabContent = '';
    if (teamTab === 'dashboard') {
        tabContent = '<div id="dashboardContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'timers') {
        tabContent = renderTimersTab(team, canManage);
    } else if (teamTab === 'members') {
        tabContent = renderMembersTab(team, members, canManage);
    } else if (teamTab === 'events') {
        tabContent = '<div id="eventsContent"><div class="empty-state">Loading...</div></div>';
    } else if (teamTab === 'chat') {
        tabContent = '<div id="chatContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'announcements') {
        tabContent = '<div id="announcementsContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'wars') {
        tabContent = '<div id="warsContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'loot') {
        tabContent = '<div id="lootContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'dkp') {
        tabContent = '<div id="dkpContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'availability') {
        tabContent = '<div id="availabilityContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'analytics') {
        tabContent = '<div id="analyticsContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'polls') {
        tabContent = '<div id="pollsContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'rosters') {
        tabContent = '<div id="rostersContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'performance') {
        tabContent = '<div id="performanceContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'recruitment') {
        tabContent = '<div id="recruitmentContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'files') {
        tabContent = '<div id="filesContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    } else if (teamTab === 'matches') {
        tabContent = '<div id="matchesContent"><div class="empty-state"><div class="spinner"></div></div></div>';
    }

    let html = `
        <button class="btn btn-secondary btn-sm" onclick="showTeamList()" style="margin-bottom:16px">&larr; Back</button>
        <div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <h2>${escapeHtml(team.name)}</h2>
                <span class="team-role ${team.my_role}">${team.my_role}</span>
            </div>
            <div class="invite-box">
                <span style="color:#64748b;font-size:0.85em">Invite Code:</span>
                <span class="invite-code">${team.invite_code}</span>
                <button class="btn btn-sm btn-secondary" onclick="copyInvite('${team.invite_code}')">Copy</button>
                <button class="btn btn-sm" id="dndBtn" onclick="toggleDND()" style="margin-left:8px;border-radius:12px;padding:4px 10px;font-size:0.8em"></button>
            </div>
        </div>

        <select class="mobile-tab-select" onchange="mobileTabSwitch(this.value)">
            <option value="dashboard" ${teamTab === 'dashboard' ? 'selected' : ''}>Dashboard</option>
            <option value="chat" ${teamTab === 'chat' ? 'selected' : ''}>Chat</option>
            <option value="announcements" ${teamTab === 'announcements' ? 'selected' : ''}>Announcements</option>
            <option value="timers" ${teamTab === 'timers' ? 'selected' : ''}>Boss Timers</option>
            <option value="events" ${teamTab === 'events' ? 'selected' : ''}>Events</option>
            <option value="members" ${teamTab === 'members' ? 'selected' : ''}>Members (${members.length})</option>
            <option value="loot" ${teamTab === 'loot' ? 'selected' : ''}>Loot</option>
            <option value="dkp" ${teamTab === 'dkp' ? 'selected' : ''}>${ptsName()}</option>
            <option value="wars" ${teamTab === 'wars' ? 'selected' : ''}>Wars</option>
            <option value="availability" ${teamTab === 'availability' ? 'selected' : ''}>Availability</option>
            <option value="polls" ${teamTab === 'polls' ? 'selected' : ''}>Polls</option>
            <option value="rosters" ${teamTab === 'rosters' ? 'selected' : ''}>Rosters</option>
            <option value="performance" ${teamTab === 'performance' ? 'selected' : ''}>Performance</option>
            <option value="recruitment" ${teamTab === 'recruitment' ? 'selected' : ''}>Recruitment</option>
            <option value="files" ${teamTab === 'files' ? 'selected' : ''}>Files</option>
            <option value="matches" ${teamTab === 'matches' ? 'selected' : ''}>Matches</option>
            ${team.premium_team ? `<option value="analytics" ${teamTab === 'analytics' ? 'selected' : ''}>Analytics</option>` : ''}
            <option value="settings" ${teamTab === 'settings' ? 'selected' : ''}>Settings</option>
        </select>
        <div class="team-layout">
            <div class="sidebar">
                <button class="tab-btn ${teamTab === 'dashboard' ? 'active' : ''}" onclick="loadAndRenderDashboard()">Dashboard</button>
                <button class="tab-btn ${teamTab === 'chat' ? 'active' : ''}" onclick="loadAndRenderChat()">Chat</button>
                <button class="tab-btn ${teamTab === 'announcements' ? 'active' : ''}" onclick="loadAndRenderAnnouncements()">Announcements</button>
                <button class="tab-btn ${teamTab === 'timers' ? 'active' : ''}" onclick="teamTab='timers';renderTeamView()">Boss Timers</button>
                <button class="tab-btn ${teamTab === 'events' ? 'active' : ''}" onclick="teamTab='events';loadAndRenderEvents()">Events</button>
                <button class="tab-btn ${teamTab === 'members' ? 'active' : ''}" onclick="teamTab='members';renderTeamView()">Members (${members.length})</button>
                <button class="tab-btn ${teamTab === 'loot' ? 'active' : ''}" onclick="loadAndRenderLoot()">Loot</button>
                <button class="tab-btn ${teamTab === 'dkp' ? 'active' : ''}" onclick="loadAndRenderDKP()">${ptsName()}</button>
                <button class="tab-btn ${teamTab === 'wars' ? 'active' : ''}" onclick="loadAndRenderWars()">Wars</button>
                <button class="tab-btn ${teamTab === 'availability' ? 'active' : ''}" onclick="loadAndRenderAvailability()">Availability</button>
                <button class="tab-btn ${teamTab === 'polls' ? 'active' : ''}" onclick="loadAndRenderPolls()">Polls</button>
                <button class="tab-btn ${teamTab === 'rosters' ? 'active' : ''}" onclick="loadAndRenderRosters()">Rosters</button>
                <button class="tab-btn ${teamTab === 'performance' ? 'active' : ''}" onclick="loadAndRenderPerformance()">Performance</button>
                <button class="tab-btn ${teamTab === 'recruitment' ? 'active' : ''}" onclick="loadAndRenderRecruitment()">Recruitment</button>
                <button class="tab-btn ${teamTab === 'files' ? 'active' : ''}" onclick="loadAndRenderFiles()">Files</button>
                <button class="tab-btn ${teamTab === 'matches' ? 'active' : ''}" onclick="loadAndRenderMatches()">Matches</button>
                ${team.premium_team ? `<button class="tab-btn ${teamTab === 'analytics' ? 'active' : ''}" onclick="loadAndRenderAnalytics()">Analytics</button>` : ''}
                <button class="tab-btn ${teamTab === 'settings' ? 'active' : ''}" onclick="teamTab='settings';renderTeamSettings()">Settings</button>
            </div>
            <div class="tab-content">
                ${tabContent}
                ${!team.premium_team ? '<div style="text-align:center;margin-top:24px;padding:8px;font-size:0.75em;color:var(--text-dim)">Powered by <b>Guild Manager</b> &middot; <a href="#" onclick="showUpgradeModal();return false" style="color:var(--accent)">Upgrade to Premium</a></div>' : ''}
            </div>
        </div>
    `;

    content.innerHTML = html;
    updateDNDBadge();
}

// --- Mobile tab switcher ---
function mobileTabSwitch(tab) {
    switch(tab) {
        case 'dashboard': loadAndRenderDashboard(); break;
        case 'chat': loadAndRenderChat(); break;
        case 'announcements': loadAndRenderAnnouncements(); break;
        case 'timers': teamTab='timers'; renderTeamView(); break;
        case 'events': teamTab='events'; loadAndRenderEvents(); break;
        case 'members': teamTab='members'; renderTeamView(); break;
        case 'loot': loadAndRenderLoot(); break;
        case 'dkp': loadAndRenderDKP(); break;
        case 'wars': loadAndRenderWars(); break;
        case 'availability': loadAndRenderAvailability(); break;
        case 'polls': loadAndRenderPolls(); break;
        case 'rosters': loadAndRenderRosters(); break;
        case 'performance': loadAndRenderPerformance(); break;
        case 'recruitment': loadAndRenderRecruitment(); break;
        case 'files': loadAndRenderFiles(); break;
        case 'matches': loadAndRenderMatches(); break;
        case 'analytics': loadAndRenderAnalytics(); break;
        case 'settings': teamTab='settings'; renderTeamSettings(); break;
    }
}
