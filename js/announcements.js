// Announcements tab

// --- Announcements ---

let teamAnnouncements = [];

async function loadAndRenderAnnouncements() {
    teamTab = 'announcements';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/announcements`);
    teamAnnouncements = data.announcements || [];
    const el = document.getElementById('announcementsContent');
    if (el) el.innerHTML = renderAnnouncementsContent();
}

function renderAnnouncementsContent() {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    let html = '';

    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addAnnouncementForm', this)">
                    <h3>+ Post Announcement</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addAnnouncementForm">
                    <div class="form-group" style="margin-top:12px">
                        <label>Title</label>
                        <input type="text" id="announcementTitle" placeholder="e.g. Weekly Raid Schedule">
                    </div>
                    <div class="form-group">
                        <label>Body (optional)</label>
                        <textarea id="announcementBody" rows="3" placeholder="Details..." style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px;width:100%;resize:vertical;font-family:inherit"></textarea>
                    </div>
                    <div style="display:flex;gap:10px;align-items:center">
                        <label style="font-size:0.85em;color:#94a3b8"><input type="checkbox" id="announcementPinned" style="accent-color:#f59e0b"> Pin</label>
                        <button class="btn btn-primary" onclick="addAnnouncement()">Post</button>
                    </div>
                </div>
            </div>
        `;
    }

    html += '<div id="announcementsListArea">' + renderAnnouncementsListOnly() + '</div>';
    return html;
}

function renderAnnouncementsListOnly() {
    const canManage = teamData.team.my_role === 'leader' || teamData.team.my_role === 'officer';
    if (teamAnnouncements.length === 0) {
        return '<div class="empty-state">No announcements yet</div>';
    }
    let html = '';
    for (const a of teamAnnouncements) {
        const date = new Date(a.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        html += `
            <div class="announcement-card ${a.pinned ? 'pinned' : ''}">
                <div class="announcement-header">
                    <div>
                        ${a.pinned ? '<span class="pin-icon">&#128204;</span>' : ''}
                        <span class="announcement-title">${escapeHtml(a.title)}</span>
                    </div>
                    <div style="display:flex;gap:4px;">
                        ${canManage ? `<button class="btn btn-sm btn-secondary" onclick="togglePin('${a.id}')" style="font-size:0.7em;padding:2px 8px">${a.pinned ? 'Unpin' : 'Pin'}</button>` : ''}
                        ${canManage || a.created_by === currentUser?.id ? `<button class="btn btn-danger btn-sm" onclick="deleteAnnouncement('${a.id}')" style="font-size:0.7em;padding:2px 8px">X</button>` : ''}
                    </div>
                </div>
                ${a.body ? `<div class="announcement-body">${escapeHtml(a.body)}</div>` : ''}
                <div class="announcement-meta">by ${escapeHtml(a.author_name)} &middot; ${date}</div>
            </div>
        `;
    }
    return html;
}

const addAnnouncement = guard('addAnnouncement', async function() {
    const title = document.getElementById('announcementTitle').value.trim();
    if (!title) return showToast('Title required');
    const body = document.getElementById('announcementBody').value.trim();
    const pinned = document.getElementById('announcementPinned').checked;
    const data = await api('POST', `/api/teams/${currentTeamId}/announcements`, { title, body: body || null, pinned });
    if (data.error) { showToast(data.error); return; }
    showToast('Announcement posted!');
    loadAndRenderAnnouncements();
});

const deleteAnnouncement = guard('deleteAnnouncement', async function(id) {
    if (!confirm('Delete this announcement?')) return;
    await api('DELETE', `/api/teams/${currentTeamId}/announcements/${id}`);
    loadAndRenderAnnouncements();
});

const togglePin = guard('togglePin', async function(id) {
    await api('POST', `/api/teams/${currentTeamId}/announcements/${id}/pin`);
    loadAndRenderAnnouncements();
});
