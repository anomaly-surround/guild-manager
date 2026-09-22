// Members tab + officer notes on members

function renderMembersTab(team, members, canManage) {
    const isLeader = team.my_role === 'leader';
    const now = Math.floor(Date.now() / 1000);
    let html = '<div class="card"><h3>Members (' + members.length + '/' + team.max_members + ')</h3>';

    for (const m of members) {
        const avatarUrl = m.avatar ? `https://cdn.discordapp.com/avatars/${m.discord_id}/${m.avatar}.png?size=64` : '';
        const isMe = m.id === currentUser.id;
        const isMemberLeader = m.role === 'leader';

        // Activity status
        let activityDot = 'inactive';
        let activityLabel = 'Never seen';
        if (m.last_seen) {
            const ago = now - m.last_seen;
            if (ago < 300) { activityDot = 'online'; activityLabel = 'Online'; }
            else if (ago < 3600) { activityDot = 'away'; activityLabel = Math.floor(ago / 60) + 'm ago'; }
            else if (ago < 86400) { activityDot = 'away'; activityLabel = Math.floor(ago / 3600) + 'h ago'; }
            else if (ago < 604800) { activityDot = 'inactive'; activityLabel = Math.floor(ago / 86400) + 'd ago'; }
            else { activityDot = 'inactive'; activityLabel = 'Inactive (7d+)'; }
        }

        html += `
            <div class="member-item">
                <img class="member-avatar" src="${avatarUrl}" onerror="this.style.background='#334155'">
                <div class="member-info">
                    <div class="member-name">${escapeHtml(m.username)}${isMe ? ' (you)' : ''}${m.premium ? ' <span style="color:#f59e0b;font-size:0.75em" title="Premium">&#11088;</span>' : ''}</div>
                    <div class="activity-text"><span class="activity-dot ${activityDot}"></span>${activityLabel}</div>
                </div>
                <span class="member-role-badge team-role ${m.role}">${m.role}</span>
                <div class="member-actions">
                    ${canManage && !isMe ? `<button class="btn btn-sm btn-secondary" onclick="openMemberNotes('${escapeHtml(m.id)}','${escapeHtml(m.username)}')" style="font-size:0.75em;padding:4px 8px">Notes</button>` : ''}
                    ${canManage && !isMe && !isMemberLeader ? `
                        ${isLeader ? `
                            <select onchange="changeRole('${escapeHtml(currentTeamId)}','${escapeHtml(m.id)}',this.value)" style="background:var(--bg-input);color:var(--text);border:1px solid #334155;border-radius:4px;padding:4px;font-size:0.75em">
                                <option value="member" ${m.role === 'member' ? 'selected' : ''}>Member</option>
                                <option value="officer" ${m.role === 'officer' ? 'selected' : ''}>Officer</option>
                            </select>
                        ` : ''}
                        <button class="btn btn-danger btn-sm" onclick="kickMember('${escapeHtml(currentTeamId)}','${escapeHtml(m.id)}','${escapeHtml(m.username)}')">Kick</button>
                    ` : ''}
                </div>
            </div>
        `;
    }

    html += '</div>';
    return html;
}

// --- Member Notes ---

const openMemberNotes = guard('openMemberNotes', async function(userId, username) {
    const data = await api('GET', `/api/teams/${currentTeamId}/members/${userId}/notes`);
    const notes = data.notes || [];
    let notesHtml = '';
    for (const n of notes) {
        const date = new Date(n.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        notesHtml += `
            <div class="note-item">
                <div class="note-text">${escapeHtml(n.note)}</div>
                <div class="note-meta">${escapeHtml(n.author_name)} &middot; ${date}
                    ${n.author_id === currentUser.id || teamData.team.my_role === 'leader' ? `<button class="btn btn-danger btn-sm" onclick="deleteMemberNote('${escapeHtml(n.id)}','${escapeHtml(userId)}','${escapeHtml(username)}')" style="font-size:0.65em;padding:1px 6px;margin-left:6px">X</button>` : ''}
                </div>
            </div>
        `;
    }
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:450px;max-width:90vw;margin:0;max-height:80vh;overflow-y:auto;">
                <h2>Notes — ${escapeHtml(username)}</h2>
                <div id="notesListModal">${notesHtml || '<div class="empty-state" style="padding:12px">No notes yet</div>'}</div>
                <div class="form-group" style="margin-top:12px">
                    <textarea id="newNoteText" rows="2" placeholder="Add a note..." style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px;width:100%;resize:vertical;font-family:inherit"></textarea>
                </div>
                <div style="display:flex;gap:8px;">
                    <button class="btn btn-primary" onclick="addMemberNote('${escapeHtml(userId)}','${escapeHtml(username)}')">Add Note</button>
                    <button class="btn" style="background:var(--bg-input);color:var(--text);" onclick="document.getElementById('deathModal').innerHTML=''">Close</button>
                </div>
            </div>
        </div>`;
});

const addMemberNote = guard('addMemberNote', async function(userId, username) {
    const note = document.getElementById('newNoteText').value.trim();
    if (!note) return;
    const data = await api('POST', `/api/teams/${currentTeamId}/members/${userId}/notes`, { note });
    if (data.error) { showToast(data.error); return; }
    openMemberNotes(userId, username);
});

const deleteMemberNote = guard('deleteMemberNote', async function(noteId, userId, username) {
    await api('DELETE', `/api/teams/${currentTeamId}/notes/${noteId}`);
    openMemberNotes(userId, username);
});
