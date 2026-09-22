// Recruitment board tab

// --- Recruitment Board ---

async function loadAndRenderRecruitment() {
    teamTab = 'recruitment';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/recruitment`);
    const el = document.getElementById('recruitmentContent');
    if (el) el.innerHTML = renderRecruitmentContent(data.posts || []);
}

function renderRecruitmentContent(posts) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    let html = '';

    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addRecruitForm', this)">
                    <h3>+ Post Opening</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addRecruitForm">
                    <div class="form-group" style="margin-top:12px">
                        <label>Title</label>
                        <input type="text" id="recruitTitle" placeholder="e.g. Looking for a Healer" maxlength="100">
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Role Needed</label>
                            <input type="text" id="recruitRole" placeholder="e.g. Healer, Tank, DPS" maxlength="50">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Description</label>
                        <textarea id="recruitDesc" rows="3" placeholder="Requirements, schedule, etc..." maxlength="500" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px;width:100%;resize:vertical;font-family:inherit"></textarea>
                    </div>
                    <div><button class="btn btn-primary" onclick="createRecruitPost()">Post Opening</button></div>
                </div>
            </div>
        `;
    }

    if (posts.length === 0) {
        html += '<div class="card"><div class="empty-state">No recruitment posts yet</div></div>';
    }

    for (const post of posts) {
        const isOpen = post.status === 'open';
        html += `<div class="card">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <div>
                    <h3>${escapeHtml(post.title)} ${isOpen ? '<span style="color:#34d399;font-size:0.7em">OPEN</span>' : '<span style="color:#ef4444;font-size:0.7em">CLOSED</span>'}</h3>
                    ${post.role_needed ? `<div style="font-size:0.85em;color:var(--accent);margin-top:2px">Role: ${escapeHtml(post.role_needed)}</div>` : ''}
                    ${post.description ? `<div style="font-size:0.85em;color:var(--text-muted);margin-top:4px">${escapeHtml(post.description)}</div>` : ''}
                    <div style="font-size:0.75em;color:var(--text-dim);margin-top:4px">by ${escapeHtml(post.created_by_name)}</div>
                </div>
                <div style="display:flex;gap:4px">
                    ${canManage && isOpen ? `<button class="btn btn-secondary btn-sm" onclick="closeRecruitPost('${post.id}')">Close</button>` : ''}
                    ${canManage && !isOpen ? `<button class="btn btn-secondary btn-sm" onclick="reopenRecruitPost('${post.id}')">Reopen</button>` : ''}
                    ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteRecruitPost('${post.id}')">X</button>` : ''}
                </div>
            </div>`;

        // Applications section
        if (canManage && post.applications) {
            html += `<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:8px">
                <div style="font-size:0.85em;font-weight:600;margin-bottom:6px">Applications (${post.applications.length})</div>`;
            if (post.applications.length === 0) {
                html += '<div style="font-size:0.8em;color:var(--text-dim)">No applications yet</div>';
            }
            for (const app of post.applications) {
                const statusColor = app.status === 'accepted' ? '#34d399' : app.status === 'rejected' ? '#ef4444' : '#f59e0b';
                html += `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px;background:var(--bg-item);border-radius:6px;margin-bottom:4px">
                    <div>
                        <span style="font-weight:600;font-size:0.9em">${escapeHtml(app.applicant_name)}</span>
                        <span style="font-size:0.75em;color:${statusColor};margin-left:6px">${app.status.toUpperCase()}</span>
                        ${app.message ? `<div style="font-size:0.8em;color:var(--text-muted);margin-top:2px">${escapeHtml(app.message)}</div>` : ''}
                    </div>
                    ${app.status === 'pending' ? `<div style="display:flex;gap:4px">
                        <button class="btn btn-sm" style="background:#065f46;color:#34d399;padding:4px 10px" onclick="reviewApplication('${post.id}','${app.id}','accepted')">Accept</button>
                        <button class="btn btn-sm" style="background:#7f1d1d;color:#ef4444;padding:4px 10px" onclick="reviewApplication('${post.id}','${app.id}','rejected')">Reject</button>
                    </div>` : ''}
                </div>`;
            }
            html += '</div>';
        } else if (!canManage) {
            const appCount = post.applicationCount || 0;
            html += `<div style="margin-top:8px;font-size:0.8em;color:var(--text-dim)">${appCount} application${appCount !== 1 ? 's' : ''}</div>`;
            if (post.myApplication) {
                const sc = post.myApplication.status === 'accepted' ? '#34d399' : post.myApplication.status === 'rejected' ? '#ef4444' : '#f59e0b';
                html += `<div style="margin-top:4px;font-size:0.85em">Your application: <span style="color:${sc};font-weight:600">${post.myApplication.status.toUpperCase()}</span></div>`;
            } else if (isOpen) {
                html += `<div style="margin-top:8px">
                    <input type="text" id="applyMsg_${post.id}" placeholder="Short message (optional)" maxlength="500" style="margin-bottom:6px;width:100%">
                    <button class="btn btn-primary btn-sm" onclick="applyToPost('${post.id}')">Apply</button>
                </div>`;
            }
        }

        html += '</div>';
    }
    return html;
}

const createRecruitPost = guard('createRecruitPost', async function() {
    const title = document.getElementById('recruitTitle').value.trim();
    if (!title) return showToast('Title required');
    const data = await api('POST', `/api/teams/${currentTeamId}/recruitment`, {
        title,
        roleNeeded: document.getElementById('recruitRole').value.trim(),
        description: document.getElementById('recruitDesc').value.trim(),
    });
    if (data.error) { showToast(data.error); return; }
    showToast('Post created!');
    loadAndRenderRecruitment();
});

const closeRecruitPost = guard('closeRecruitPost', async function(postId) {
    await api('PUT', `/api/teams/${currentTeamId}/recruitment/${postId}`, { status: 'closed' });
    loadAndRenderRecruitment();
});

const reopenRecruitPost = guard('reopenRecruitPost', async function(postId) {
    await api('PUT', `/api/teams/${currentTeamId}/recruitment/${postId}`, { status: 'open' });
    loadAndRenderRecruitment();
});

const deleteRecruitPost = guard('deleteRecruitPost', async function(postId) {
    await api('DELETE', `/api/teams/${currentTeamId}/recruitment/${postId}`);
    loadAndRenderRecruitment();
});

const applyToPost = guard('applyToPost', async function(postId) {
    const msg = document.getElementById(`applyMsg_${postId}`)?.value?.trim() || '';
    const data = await api('POST', `/api/teams/${currentTeamId}/recruitment/${postId}/apply`, { message: msg });
    if (data.error) { showToast(data.error); return; }
    showToast('Application submitted!');
    loadAndRenderRecruitment();
});

const reviewApplication = guard('reviewApplication', async function(postId, appId, status) {
    await api('PUT', `/api/teams/${currentTeamId}/recruitment/${postId}/applications/${appId}`, { status });
    showToast(status === 'accepted' ? 'Accepted!' : 'Rejected');
    loadAndRenderRecruitment();
});
