// Polls & voting tab

// --- Polls & Voting ---

async function loadAndRenderPolls() {
    teamTab = 'polls';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/polls`);
    const el = document.getElementById('pollsContent');
    if (el) el.innerHTML = renderPollsContent(data.polls || []);
}

function renderPollsContent(polls) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    let html = '';

    // Create poll form (any member can create)
    html += `
        <div class="card">
            <div class="collapsible-header" onclick="toggleSection('addPollForm', this)">
                <h3>+ Create Poll</h3>
                <span class="toggle-arrow">&#9660;</span>
            </div>
            <div class="collapsible-body" id="addPollForm">
                <div class="form-group" style="margin-top:12px">
                    <label>Question</label>
                    <input type="text" id="pollQuestion" placeholder="e.g. Which boss do we farm next?" maxlength="200">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Type</label>
                        <select id="pollType" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                            <option value="single">Single Choice</option>
                            <option value="multi">Multiple Choice</option>
                        </select>
                    </div>
                </div>
                <div id="pollOptionsContainer">
                    <label>Options</label>
                    <div class="form-group"><input type="text" class="poll-option-input" placeholder="Option 1" maxlength="100"></div>
                    <div class="form-group"><input type="text" class="poll-option-input" placeholder="Option 2" maxlength="100"></div>
                </div>
                <button class="btn btn-secondary btn-sm" onclick="addPollOptionField()" style="margin:8px 0">+ Add Option</button>
                <div><button class="btn btn-primary" onclick="createPoll()">Create Poll</button></div>
            </div>
        </div>
    `;

    // Polls list
    if (polls.length === 0) {
        html += '<div class="card"><div class="empty-state">No polls yet — create one above!</div></div>';
    }
    for (const poll of polls) {
        const totalVotes = poll.options.reduce((sum, o) => sum + o.votes.length, 0);
        const isExpired = poll.expires_at && poll.expires_at < Math.floor(Date.now() / 1000);
        const isClosed = poll.closed || isExpired;
        const hasVoted = poll.myVotes.length > 0;

        html += `<div class="card">
            <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <div>
                    <h3>${escapeHtml(poll.question)}</h3>
                    <div style="font-size:0.75em;color:var(--text-dim);margin-top:2px">
                        by ${escapeHtml(poll.created_by_name)} &middot; ${poll.poll_type === 'multi' ? 'Multi-choice' : 'Single choice'}
                        &middot; ${totalVotes} vote${totalVotes !== 1 ? 's' : ''}
                        ${isClosed ? ' &middot; <span style="color:#ef4444">Closed</span>' : ''}
                    </div>
                </div>
                <div style="display:flex;gap:4px">
                    ${!isClosed && canManage ? `<button class="btn btn-secondary btn-sm" onclick="closePoll('${poll.id}')">Close</button>` : ''}
                    ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deletePoll('${poll.id}')">X</button>` : ''}
                </div>
            </div>
            <div style="margin-top:12px">`;

        for (const opt of poll.options) {
            const pct = totalVotes > 0 ? Math.round((opt.votes.length / totalVotes) * 100) : 0;
            const isMyVote = poll.myVotes.includes(opt.id);
            const voters = opt.votes.map(v => escapeHtml(v.username)).join(', ');

            html += `<div style="margin-bottom:8px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:2px">
                    <span style="font-size:0.9em;${isMyVote ? 'font-weight:700;color:var(--accent)' : ''}">${escapeHtml(opt.label)}</span>
                    <span style="font-size:0.8em;color:var(--text-muted)">${opt.votes.length} (${pct}%)</span>
                </div>
                <div style="background:var(--bg-input);border-radius:6px;height:24px;overflow:hidden;position:relative;cursor:${isClosed ? 'default' : 'pointer'}"
                    ${!isClosed ? `onclick="votePoll('${poll.id}','${opt.id}','${poll.poll_type}')"` : ''}
                    title="${voters || 'No votes'}">
                    <div style="background:linear-gradient(90deg,var(--accent),var(--accent2));height:100%;width:${pct}%;border-radius:6px;transition:width 0.3s"></div>
                </div>
            </div>`;
        }
        html += '</div></div>';
    }

    return html;
}

function addPollOptionField() {
    const container = document.getElementById('pollOptionsContainer');
    const count = container.querySelectorAll('.poll-option-input').length;
    if (count >= 10) return showToast('Max 10 options');
    const div = document.createElement('div');
    div.className = 'form-group';
    div.innerHTML = `<input type="text" class="poll-option-input" placeholder="Option ${count + 1}" maxlength="100">`;
    container.appendChild(div);
}

const createPoll = guard('createPoll', async function() {
    const question = document.getElementById('pollQuestion').value.trim();
    if (!question) return showToast('Question required');
    const inputs = document.querySelectorAll('.poll-option-input');
    const options = [...inputs].map(i => i.value.trim()).filter(Boolean);
    if (options.length < 2) return showToast('At least 2 options required');

    const data = await api('POST', `/api/teams/${currentTeamId}/polls`, {
        question,
        pollType: document.getElementById('pollType').value,
        options,
    });
    if (data.error) { showToast(data.error); return; }
    showToast('Poll created!');
    loadAndRenderPolls();
});

const votePoll = guard('votePoll', async function(pollId, optionId, pollType) {
    const data = await api('POST', `/api/teams/${currentTeamId}/polls/${pollId}/vote`, {
        optionIds: [optionId],
    });
    if (data.error) { showToast(data.error); return; }
    loadAndRenderPolls();
});

const closePoll = guard('closePoll', async function(pollId) {
    await api('POST', `/api/teams/${currentTeamId}/polls/${pollId}/close`);
    loadAndRenderPolls();
});

const deletePoll = guard('deletePoll', async function(pollId) {
    await api('DELETE', `/api/teams/${currentTeamId}/polls/${pollId}`);
    loadAndRenderPolls();
});
