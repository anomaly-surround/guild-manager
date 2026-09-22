// Availability tab

// --- Availability ---

const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

async function loadAndRenderAvailability() {
    teamTab = 'availability';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/availability`);
    const slots = data.slots || [];
    const el = document.getElementById('availabilityContent');
    if (el) el.innerHTML = renderAvailabilityContent(slots);
}

function renderAvailabilityContent(slots) {
    // Group by user
    const byUser = {};
    for (const s of slots) {
        if (!byUser[s.user_id]) byUser[s.user_id] = { username: s.username, slots: [] };
        byUser[s.user_id].slots.push(s);
    }

    // My slots editor
    let html = `
        <div class="card">
            <div class="collapsible-header" onclick="toggleSection('editAvailForm', this)">
                <h3>+ Set My Availability</h3>
                <span class="toggle-arrow">&#9660;</span>
            </div>
            <div class="collapsible-body" id="editAvailForm">
                <div id="myAvailSlots"></div>
                <button class="btn btn-sm btn-secondary" onclick="addAvailSlot()" style="margin-top:8px">+ Add Slot</button>
                <button class="btn btn-primary btn-sm" onclick="saveAvailability()" style="margin-top:8px;margin-left:8px">Save</button>
            </div>
        </div>
    `;

    // Team grid view
    html += '<div class="card"><h3>Team Availability</h3>';
    if (Object.keys(byUser).length === 0) {
        html += '<div class="empty-state">No availability set yet</div>';
    } else {
        html += '<div class="avail-grid">';
        html += '<div class="avail-header"></div>';
        for (let d = 0; d < 7; d++) html += `<div class="avail-header">${dayNames[d]}</div>`;

        for (const [userId, userData] of Object.entries(byUser)) {
            html += `<div class="avail-header" style="text-align:left;padding-left:6px">${escapeHtml(userData.username)}</div>`;
            for (let d = 0; d < 7; d++) {
                const daySlots = userData.slots.filter(s => s.day === d);
                html += '<div class="avail-cell">';
                for (const s of daySlots) {
                    html += `<div class="avail-slot">${s.start_time}-${s.end_time}</div>`;
                }
                html += '</div>';
            }
        }
        html += '</div>';
    }
    html += '</div>';

    return html;
}

function addAvailSlot() {
    const container = document.getElementById('myAvailSlots');
    const div = document.createElement('div');
    div.className = 'form-row';
    div.style.marginTop = '6px';
    div.innerHTML = `
        <div class="form-group" style="max-width:110px">
            <select class="avail-day" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:8px;border-radius:8px">
                ${dayNames.map((d,i) => `<option value="${i}">${d}</option>`).join('')}
            </select>
        </div>
        <div class="form-group" style="max-width:110px">
            <input type="time" class="avail-start" style="color-scheme:var(--color-scheme)">
        </div>
        <div class="form-group" style="max-width:110px">
            <input type="time" class="avail-end" style="color-scheme:var(--color-scheme)">
        </div>
        <button class="btn btn-danger btn-sm" onclick="this.parentElement.remove()" style="align-self:center">X</button>
    `;
    container.appendChild(div);
}

const saveAvailability = guard('saveAvailability', async function() {
    const rows = document.querySelectorAll('#myAvailSlots .form-row');
    const slots = [];
    for (const row of rows) {
        const day = parseInt(row.querySelector('.avail-day').value);
        const startTime = row.querySelector('.avail-start').value;
        const endTime = row.querySelector('.avail-end').value;
        if (startTime && endTime) slots.push({ day, startTime, endTime });
    }
    const data = await api('PUT', `/api/teams/${currentTeamId}/availability`, { slots });
    if (data.error) { showToast(data.error); return; }
    showToast('Availability saved!');
    loadAndRenderAvailability();
});
