// Roster / lineup builder tab

// --- Roster / Lineup Builder ---

async function loadAndRenderRosters() {
    teamTab = 'rosters';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/rosters`);
    const el = document.getElementById('rostersContent');
    if (el) el.innerHTML = renderRostersContent(data.rosters || []);
}

function renderRostersContent(rosters) {
    const team = teamData.team;
    const members = teamData.members;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    let html = '';

    if (canManage) {
        const memberOpts = members.map(m => `<option value="${m.user_id}">${escapeHtml(m.username)}</option>`).join('');
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addRosterForm', this)">
                    <h3>+ Create Roster</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addRosterForm">
                    <div class="form-group" style="margin-top:12px">
                        <label>Roster Name</label>
                        <input type="text" id="rosterName" placeholder="e.g. Friday GvG Lineup" maxlength="100">
                    </div>
                    <div id="rosterSlotsContainer">
                        <label>Slots</label>
                        <div class="roster-slot-row" style="display:flex;gap:8px;margin-bottom:6px">
                            <input type="text" class="roster-role-input" placeholder="Role (e.g. Tank)" maxlength="50" style="flex:1">
                            <select class="roster-member-select" style="flex:1;background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:8px;border-radius:8px">
                                <option value="">-- Unassigned --</option>${memberOpts}
                            </select>
                        </div>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="addRosterSlotField()" style="margin:8px 0">+ Add Slot</button>
                    <div><button class="btn btn-primary" onclick="createRoster()">Create Roster</button></div>
                </div>
            </div>
        `;
    }

    if (rosters.length === 0) {
        html += '<div class="card"><div class="empty-state">No rosters yet</div></div>';
    }

    for (const roster of rosters) {
        html += `<div class="card">
            <div style="display:flex;justify-content:space-between;align-items:center">
                <div>
                    <h3>${escapeHtml(roster.name)}</h3>
                    <div style="font-size:0.75em;color:var(--text-dim)">by ${escapeHtml(roster.created_by_name)} &middot; ${roster.slots.length} slot${roster.slots.length !== 1 ? 's' : ''}</div>
                </div>
                <div style="display:flex;gap:4px">
                    ${canManage ? `<button class="btn btn-secondary btn-sm" onclick="editRoster('${roster.id}')">Edit</button>` : ''}
                    ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteRoster('${roster.id}')">X</button>` : ''}
                </div>
            </div>
            <div style="margin-top:12px">`;

        for (const slot of roster.slots) {
            html += `
                <div class="dkp-row">
                    <span style="font-weight:600;color:var(--accent)">${escapeHtml(slot.role_name)}</span>
                    <span>${slot.assigned_name ? escapeHtml(slot.assigned_name) : '<span style="color:var(--text-dim)">— Empty —</span>'}</span>
                </div>`;
        }
        if (roster.slots.length === 0) html += '<div class="empty-state" style="padding:8px">No slots defined</div>';
        html += '</div></div>';
    }

    return html;
}

function addRosterSlotField() {
    const container = document.getElementById('rosterSlotsContainer');
    const count = container.querySelectorAll('.roster-slot-row').length;
    if (count >= 30) return showToast('Max 30 slots');
    const members = teamData.members;
    const memberOpts = members.map(m => `<option value="${m.user_id}">${escapeHtml(m.username)}</option>`).join('');
    const div = document.createElement('div');
    div.className = 'roster-slot-row';
    div.style.cssText = 'display:flex;gap:8px;margin-bottom:6px';
    div.innerHTML = `
        <input type="text" class="roster-role-input" placeholder="Role" maxlength="50" style="flex:1">
        <select class="roster-member-select" style="flex:1;background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:8px;border-radius:8px">
            <option value="">-- Unassigned --</option>${memberOpts}
        </select>`;
    container.appendChild(div);
}

const createRoster = guard('createRoster', async function() {
    const name = document.getElementById('rosterName').value.trim();
    if (!name) return showToast('Roster name required');

    const roles = document.querySelectorAll('.roster-role-input');
    const selects = document.querySelectorAll('.roster-member-select');
    const slots = [];
    roles.forEach((r, i) => {
        if (r.value.trim()) slots.push({ roleName: r.value.trim(), userId: selects[i]?.value || null });
    });

    const data = await api('POST', `/api/teams/${currentTeamId}/rosters`, { name, slots });
    if (data.error) { showToast(data.error); return; }
    showToast('Roster created!');
    loadAndRenderRosters();
});

const editRoster = guard('editRoster', async function(rosterId) {
    const data = await api('GET', `/api/teams/${currentTeamId}/rosters`);
    const roster = (data.rosters || []).find(r => r.id === rosterId);
    if (!roster) return;
    const members = teamData.members;
    const memberOpts = members.map(m => `<option value="${m.user_id}">${escapeHtml(m.username)}</option>`).join('');

    let slotsHtml = '';
    for (const s of roster.slots) {
        slotsHtml += `<div style="display:flex;gap:8px;margin-bottom:6px">
            <input type="text" class="edit-roster-role" value="${escapeHtml(s.role_name)}" style="flex:1" maxlength="50">
            <select class="edit-roster-member" style="flex:1;background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:8px;border-radius:8px">
                <option value="">-- Unassigned --</option>${memberOpts}
            </select>
        </div>`;
    }

    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:500px;max-width:90vw;margin:0;max-height:80vh;overflow-y:auto">
                <h2>Edit Roster: ${escapeHtml(roster.name)}</h2>
                <div id="editRosterSlots">${slotsHtml}</div>
                <button class="btn btn-secondary btn-sm" onclick="addEditRosterSlot()" style="margin:8px 0">+ Add Slot</button>
                <div style="display:flex;gap:8px;margin-top:8px">
                    <button class="btn btn-primary" onclick="saveRosterSlots('${rosterId}')">Save</button>
                    <button class="btn" style="background:var(--bg-input);color:var(--text)" onclick="document.getElementById('deathModal').innerHTML=''">Cancel</button>
                </div>
            </div>
        </div>`;

    // Set selected values after DOM is ready
    setTimeout(() => {
        const selects = document.querySelectorAll('.edit-roster-member');
        roster.slots.forEach((s, i) => { if (selects[i] && s.user_id) selects[i].value = s.user_id; });
    }, 50);
});

function addEditRosterSlot() {
    const container = document.getElementById('editRosterSlots');
    const members = teamData.members;
    const memberOpts = members.map(m => `<option value="${m.user_id}">${escapeHtml(m.username)}</option>`).join('');
    const div = document.createElement('div');
    div.style.cssText = 'display:flex;gap:8px;margin-bottom:6px';
    div.innerHTML = `
        <input type="text" class="edit-roster-role" placeholder="Role" style="flex:1" maxlength="50">
        <select class="edit-roster-member" style="flex:1;background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:8px;border-radius:8px">
            <option value="">-- Unassigned --</option>${memberOpts}
        </select>`;
    container.appendChild(div);
}

const saveRosterSlots = guard('saveRosterSlots', async function(rosterId) {
    const roles = document.querySelectorAll('.edit-roster-role');
    const selects = document.querySelectorAll('.edit-roster-member');
    const slots = [];
    roles.forEach((r, i) => {
        if (r.value.trim()) slots.push({ roleName: r.value.trim(), userId: selects[i]?.value || null });
    });
    await api('PUT', `/api/teams/${currentTeamId}/rosters/${rosterId}/slots`, { slots });
    document.getElementById('deathModal').innerHTML = '';
    showToast('Roster updated!');
    loadAndRenderRosters();
});

const deleteRoster = guard('deleteRoster', async function(rosterId) {
    await api('DELETE', `/api/teams/${currentTeamId}/rosters/${rosterId}`);
    loadAndRenderRosters();
});
