// Events tab: list, RSVP, attendance, templates

// --- Events ---

let teamEvents = [];

async function loadAndRenderEvents() {
    teamTab = 'events';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/events`);
    teamEvents = data.events || [];
    const el = document.getElementById('eventsContent');
    if (el) el.innerHTML = renderEventsContent();
}

function renderEventsContent() {
    const now = Date.now();
    const canManage = teamData.team.my_role === 'leader' || teamData.team.my_role === 'officer';

    let html = `
        <div class="card">
            <div class="collapsible-header" onclick="toggleSection('addEventForm', this)">
                <h3>+ Create Event</h3>
                <span class="toggle-arrow">&#9660;</span>
            </div>
            <div class="collapsible-body" id="addEventForm">
                <div class="form-row" style="margin-top:12px">
                    <div class="form-group">
                        <label>Title</label>
                        <input type="text" id="eventTitle" placeholder="e.g. Guild War">
                    </div>
                    <div class="form-group" style="max-width:140px">
                        <label>Type</label>
                        <select id="eventType" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                            <option value="scrim">Scrim</option>
                            <option value="raid">Raid</option>
                            <option value="gvg">GvG</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                </div>
                <div class="form-row" style="margin-top:8px">
                    <div class="form-group">
                        <label>Date & Time</label>
                        <input type="datetime-local" id="eventDateTime" style="color-scheme:var(--color-scheme)">
                    </div>
                    <div class="form-group" style="max-width:100px">
                        <label>Duration (min)</label>
                        <input type="number" id="eventDuration" value="60" min="15">
                    </div>
                    <div class="form-group" style="max-width:140px">
                        <label>Repeat</label>
                        <select id="eventRecurrence" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                            <option value="none">No repeat</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="biweekly">Biweekly</option>
                            <option value="monthly">Monthly</option>
                        </select>
                    </div>
                </div>
                <div class="form-group" style="margin-top:8px">
                    <label>Description (optional)</label>
                    <input type="text" id="eventDesc" placeholder="Details, links, etc.">
                </div>
                <div style="margin-top:10px">
                    <button class="btn btn-primary" onclick="addEvent()">Create Event</button>
                </div>
            </div>
        </div>
    `;

    html += '<div id="eventsListArea">' + renderEventsListOnly() + '</div>';
    return html;
}

function renderEventsListOnly() {
    const now = Date.now();
    const canManage = teamData.team.my_role === 'leader' || teamData.team.my_role === 'officer';
    let html = '';
    const upcoming = teamEvents.filter(e => e.event_time + (e.duration_minutes || 60) * 60000 > now);
    const past = teamEvents.filter(e => e.event_time + (e.duration_minutes || 60) * 60000 <= now);

    if (upcoming.length === 0 && past.length === 0) {
        html += '<div class="empty-state">No events yet</div>';
    }

    if (upcoming.length > 0) {
        html += '<h3 style="color:#94a3b8;margin:16px 0 10px">Upcoming</h3>';
        for (const e of upcoming) html += renderEventCard(e, canManage, false);
    }

    if (past.length > 0) {
        html += '<h3 style="color:#64748b;margin:16px 0 10px">Past</h3>';
        for (const e of past.slice(-10).reverse()) html += renderEventCard(e, canManage, true);
    }

    return html;
}

function renderEventCard(e, canManage, isPast) {
    const eventDate = new Date(e.event_time);
    const dateStr = eventDate.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    const timeStr = eventDate.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const remaining = e.event_time - Date.now();
    const isStarting = remaining <= 0 && remaining > -(e.duration_minutes || 60) * 60000;

    let countdown = '';
    if (isStarting) countdown = '<span style="color:#ef4444;font-weight:600"> LIVE NOW</span>';
    else if (remaining > 0) countdown = ` (in ${formatTimeLong(remaining)})`;

    return `
        <div class="event-card ${isPast ? 'past' : ''}" data-event-id="${e.id}">
            <div class="event-header">
                <div>
                    <span class="event-title">${escapeHtml(e.title)}</span>
                    <span class="event-type-badge ${e.event_type}">${e.event_type}</span>
                    ${e.recurrence ? `<span class="event-type-badge" style="background:#1e3a5f;color:#60a5fa">${e.recurrence}</span>` : ''}
                </div>
                ${canManage || e.created_by === currentUser?.id ? `<button class="btn btn-danger btn-sm" onclick="deleteEvent('${e.id}')">X</button>` : ''}
            </div>
            <div class="event-time">${dateStr} at ${timeStr} (${e.duration_minutes || 60}min)<span class="event-countdown">${countdown}</span></div>
            ${e.description ? `<div class="event-desc">${escapeHtml(e.description)}</div>` : ''}
            <div class="event-time" style="margin-top:4px;font-size:0.75em">by ${escapeHtml(e.creator_name)}</div>
            <div class="rsvp-bar">
                <button class="rsvp-btn ${e.my_rsvp === 'going' ? 'active-going' : ''}" onclick="rsvpEvent('${e.id}','going')">Going</button>
                <button class="rsvp-btn ${e.my_rsvp === 'maybe' ? 'active-maybe' : ''}" onclick="rsvpEvent('${e.id}','maybe')">Maybe</button>
                <button class="rsvp-btn ${e.my_rsvp === 'not_going' ? 'active-not' : ''}" onclick="rsvpEvent('${e.id}','not_going')">Can't</button>
                <span class="rsvp-counts">${e.going_count} going &middot; ${e.maybe_count} maybe &middot; ${e.not_going_count} can't</span>
            </div>
        </div>
    `;
}

const addEvent = guard('addEvent', async function() {
    const title = document.getElementById('eventTitle').value.trim();
    const dateTime = document.getElementById('eventDateTime').value;
    if (!title || !dateTime) return showToast('Title and date/time required');

    const eventTime = new Date(dateTime).getTime();
    if (isNaN(eventTime)) return;

    const recurrence = document.getElementById('eventRecurrence').value;
    const data = await api('POST', `/api/teams/${currentTeamId}/events`, {
        title,
        eventType: document.getElementById('eventType').value,
        eventTime,
        durationMinutes: parseInt(document.getElementById('eventDuration').value) || 60,
        description: document.getElementById('eventDesc').value.trim() || null,
        recurrence: recurrence !== 'none' ? recurrence : null,
    });

    if (data.error) { showToast(data.error); return; }
    showToast(`Event "${title}" created`);
    loadAndRenderEvents();
});

const rsvpEvent = guard('rsvpEvent', async function(eventId, status) {
    await api('POST', `/api/teams/${currentTeamId}/events/${eventId}/rsvp`, { status });
    loadAndRenderEvents();
});

const deleteEvent = guard('deleteEvent', async function(eventId) {
    if (!confirm('Delete this event?')) return;
    await api('DELETE', `/api/teams/${currentTeamId}/events/${eventId}`);
    showToast('Event deleted');
    loadAndRenderEvents();
});
