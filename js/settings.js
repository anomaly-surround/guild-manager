// Team settings tab (webhooks, notifications, rules, invites, cleanup, ownership, customization, DKP decay)

async function renderTeamSettings() {
    teamTab = 'settings';
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';

    const [settings, rolesData] = await Promise.all([
        api('GET', `/api/teams/${currentTeamId}/settings`),
        api('GET', `/api/teams/${currentTeamId}/roles`),
    ]);
    _pointsName = settings.pointsName || 'DKP';
    const roles = rolesData.roles || {};
    settings._roleLeader = roles.leader?.displayName || '';
    settings._roleOfficer = roles.officer?.displayName || '';
    settings._roleMember = roles.member?.displayName || '';

    const members = teamData.members;

    const isLeader = team.my_role === 'leader';
    const otherMembers = members.filter(m => m.id !== currentUser.id);

    let settingsContent = '';

    if (!canManage) {
        settingsContent = '<div class="card"><p style="color:var(--text-dim);font-size:0.85em">Only officers and leaders can manage settings.</p></div>';
    } else {
        settingsContent = `
        <!-- Team Info -->
        <div class="card">
            <h3>Team Info</h3>
            <div class="form-group" style="margin-top:8px">
                <label>Description</label>
                <textarea id="teamDesc" rows="2" placeholder="What's your team about?" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px;width:100%;resize:vertical;font-family:inherit">${settings.teamDescription || ''}</textarea>
            </div>
            <div class="form-row" style="margin-top:8px">
                <div class="form-group" style="max-width:200px">
                    <label>Timezone</label>
                    <select id="teamTimezone" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                        ${['Asia/Manila','America/New_York','America/Chicago','America/Denver','America/Los_Angeles','Europe/London','Europe/Paris','Europe/Berlin','Asia/Tokyo','Asia/Seoul','Asia/Singapore','Australia/Sydney','Pacific/Auckland']
                            .map(tz => `<option value="${tz}" ${settings.timezone === tz ? 'selected' : ''}>${tz}</option>`).join('')}
                    </select>
                </div>
                <div style="align-self:flex-end"><button class="btn btn-primary btn-sm" onclick="saveTeamInfo()">Save</button></div>
            </div>
        </div>

        <!-- Invite Settings -->
        <div class="card">
            <h3>Invite Settings</h3>
            <div style="display:flex;gap:12px 20px;flex-wrap:wrap;font-size:0.85em;color:var(--text-muted);margin-top:8px">
                <label><input type="checkbox" id="invitesEnabled" ${settings.invitesEnabled !== false ? 'checked' : ''} onchange="saveInviteSettings()" style="accent-color:#5865F2"> Accept new members</label>
                <label><input type="checkbox" id="inviteApproval" ${settings.inviteApproval ? 'checked' : ''} onchange="saveInviteSettings()" style="accent-color:#5865F2"> Require approval to join</label>
            </div>
            <div id="joinRequestsArea" style="margin-top:12px"></div>
        </div>

        <!-- Public timer page -->
        <div class="card">
            <h3>Public timer page</h3>
            <p style="font-size:0.85em;color:var(--text-muted);margin:6px 0 10px">A read-only page of your boss timers that anyone with the link can open. Pin it in Discord.</p>
            <label style="font-size:0.85em;color:var(--text-muted)"><input type="checkbox" id="publicTimers" ${settings.publicToken ? 'checked' : ''} onchange="savePublicTimers()" style="accent-color:#5865F2"> Enable public timer page</label>
            ${settings.publicToken ? `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px">
                <code id="publicTimersUrl" style="font-size:0.78em;padding:6px 8px;background:var(--surface-2);border-radius:6px;word-break:break-all">${location.origin}${location.pathname.replace(/[^/]*$/, '')}timers.html?t=${settings.publicToken}</code>
                <button class="btn btn-sm btn-secondary" onclick="copyPublicTimersUrl()">Copy link</button>
                <a class="btn btn-sm btn-secondary" href="timers.html?t=${settings.publicToken}" target="_blank" rel="noopener">Open</a>
            </div>` : ''}
        </div>

        <!-- Discord Notifications -->
        <div class="card">
            <h3>Discord Notifications</h3>
            <div class="form-row" style="margin-top:8px">
                <div class="form-group">
                    <label>Webhook URL ${(settings.webhookUrlSet || settings.webhookUrl) ? '<span style="color:#34d399;font-size:0.85em">✓ saved</span>' : ''}</label>
                    <input type="text" id="webhookUrl" placeholder="${(settings.webhookUrlSet || settings.webhookUrl) ? '(saved — paste a new URL to replace)' : 'https://discord.com/api/webhooks/...'}" value="">
                </div>
                <div><button class="btn btn-primary btn-sm" onclick="saveWebhook()">Save</button></div>
                <div><button class="btn btn-secondary btn-sm" onclick="testWebhook()">Test</button></div>
                <div><button class="btn btn-secondary btn-sm" style="background:#7f1d1d;color:#fca5a5" onclick="clearWebhook()">Clear</button></div>
            </div>
            <div style="margin-top:12px;display:flex;gap:12px 20px;flex-wrap:wrap;font-size:0.85em;color:var(--text-muted)">
                <label><input type="checkbox" id="onWarning" ${settings.onWarning ? 'checked' : ''} onchange="saveNotifSettings()" style="accent-color:#5865F2"> Boss warning</label>
                <label><input type="checkbox" id="onSpawn" ${settings.onSpawn ? 'checked' : ''} onchange="saveNotifSettings()" style="accent-color:#5865F2"> Boss spawn</label>
                <label><input type="checkbox" id="onAnnouncement" ${settings.onAnnouncement !== false ? 'checked' : ''} onchange="saveNotifSettings()" style="accent-color:#5865F2"> Announcements</label>
                <label><input type="checkbox" id="onEvent" ${settings.onEvent !== false ? 'checked' : ''} onchange="saveNotifSettings()" style="accent-color:#5865F2"> Events</label>
                <label><input type="checkbox" id="onWar" ${settings.onWar !== false ? 'checked' : ''} onchange="saveNotifSettings()" style="accent-color:#5865F2"> War results</label>
            </div>
            <div class="form-row" style="margin-top:10px">
                <div class="form-group" style="max-width:180px">
                    <label>Event reminder (minutes before)</label>
                    <input type="number" id="eventReminderMin" value="${settings.eventReminderMinutes || 15}" min="1" max="120">
                </div>
                <div style="align-self:flex-end"><button class="btn btn-secondary btn-sm" onclick="saveNotifSettings()">Save</button></div>
            </div>
        </div>

        <!-- Team Rules -->
        <div class="card">
            <h3>Permissions & Defaults</h3>
            <div style="display:flex;gap:12px 20px;flex-wrap:wrap;font-size:0.85em;color:var(--text-muted);margin-top:8px">
                <label><input type="checkbox" id="membersCreateEvents" ${settings.membersCreateEvents !== false ? 'checked' : ''} onchange="saveTeamRules()" style="accent-color:#5865F2"> Members can create events</label>
            </div>
            <div class="form-row" style="margin-top:12px">
                <div class="form-group" style="max-width:160px">
                    <label>Default event duration (min)</label>
                    <input type="number" id="defaultEventDuration" value="${settings.defaultEventDuration || 60}" min="15" max="480">
                </div>
                <div class="form-group" style="max-width:160px">
                    <label>Inactive threshold (days)</label>
                    <input type="number" id="inactiveDays" value="${settings.inactiveDays || 7}" min="1" max="90">
                </div>
                <div class="form-group" style="max-width:180px">
                    <label>Points System Name</label>
                    <input type="text" id="pointsName" value="${escapeHtml(settings.pointsName || 'DKP')}" maxlength="20" placeholder="e.g. DKP, Credits, Rep">
                </div>
                <div class="form-group" style="max-width:160px">
                    <label>Starting ${escapeHtml(settings.pointsName || 'DKP')}</label>
                    <input type="number" id="startingDkp" value="${settings.startingDkp || 0}" min="0">
                </div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="saveTeamRules()" style="margin-top:8px">Save</button>
        </div>

        <!-- Auto Cleanup -->
        <div class="card">
            <h3>Auto Cleanup</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Set to 0 to disable auto-deletion.</p>
            <div class="form-row">
                <div class="form-group" style="max-width:200px">
                    <label>Delete old events after (days)</label>
                    <input type="number" id="autoDeleteEvents" value="${settings.autoDeleteEventsDays || 0}" min="0">
                </div>
                <div class="form-group" style="max-width:200px">
                    <label>Delete old chat after (days)</label>
                    <input type="number" id="autoDeleteChat" value="${settings.autoDeleteChatDays || 0}" min="0">
                </div>
                <div style="align-self:flex-end"><button class="btn btn-secondary btn-sm" onclick="saveCleanup()">Save</button></div>
            </div>
        </div>

        <!-- Premium: Channel Webhooks -->
        ${premiumGate(`
        <div class="card">
            <h3>Channel-Specific Webhooks</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Override the default webhook for specific notification types. Leave empty to keep the existing saved value.</p>
            <div class="form-group" style="margin-top:8px">
                <label>Boss Alerts Webhook ${settings.webhookBossSet ? '<span style="color:#34d399;font-size:0.85em">✓ saved</span>' : ''}</label>
                <div style="display:flex;gap:6px">
                    <input type="text" id="webhookBoss" placeholder="${settings.webhookBossSet ? '(saved — paste a new URL to replace)' : 'https://discord.com/api/webhooks/...'}" value="">
                    ${settings.webhookBossSet ? '<button class="btn btn-sm btn-secondary" onclick="clearChannelWebhook(\'Boss\')">Clear</button>' : ''}
                </div>
            </div>
            <div class="form-group" style="margin-top:6px">
                <label>Events Webhook ${settings.webhookEventsSet ? '<span style="color:#34d399;font-size:0.85em">✓ saved</span>' : ''}</label>
                <div style="display:flex;gap:6px">
                    <input type="text" id="webhookEvents" placeholder="${settings.webhookEventsSet ? '(saved — paste a new URL to replace)' : 'https://discord.com/api/webhooks/...'}" value="">
                    ${settings.webhookEventsSet ? '<button class="btn btn-sm btn-secondary" onclick="clearChannelWebhook(\'Events\')">Clear</button>' : ''}
                </div>
            </div>
            <div class="form-group" style="margin-top:6px">
                <label>War Results Webhook ${settings.webhookWarsSet ? '<span style="color:#34d399;font-size:0.85em">✓ saved</span>' : ''}</label>
                <div style="display:flex;gap:6px">
                    <input type="text" id="webhookWars" placeholder="${settings.webhookWarsSet ? '(saved — paste a new URL to replace)' : 'https://discord.com/api/webhooks/...'}" value="">
                    ${settings.webhookWarsSet ? '<button class="btn btn-sm btn-secondary" onclick="clearChannelWebhook(\'Wars\')">Clear</button>' : ''}
                </div>
            </div>
            <div class="form-group" style="margin-top:6px">
                <label>Announcements Webhook ${settings.webhookAnnouncementsSet ? '<span style="color:#34d399;font-size:0.85em">✓ saved</span>' : ''}</label>
                <div style="display:flex;gap:6px">
                    <input type="text" id="webhookAnnouncements" placeholder="${settings.webhookAnnouncementsSet ? '(saved — paste a new URL to replace)' : 'https://discord.com/api/webhooks/...'}" value="">
                    ${settings.webhookAnnouncementsSet ? '<button class="btn btn-sm btn-secondary" onclick="clearChannelWebhook(\'Announcements\')">Clear</button>' : ''}
                </div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="saveChannelWebhooks()" style="margin-top:8px">Save</button>
        </div>
        `, 'Channel Webhooks')}

        <!-- Premium: Customization -->
        ${premiumGate(`
        <div class="card">
            <h3>Customization</h3>
            <div class="form-row" style="margin-top:8px">
                <div class="form-group" style="max-width:180px">
                    <label>Accent Color</label>
                    <input type="color" id="accentColor" value="${settings.accentColor || '#7c3aed'}" style="height:40px;padding:2px;background:var(--bg-input);border:1px solid var(--border-input);border-radius:8px;cursor:pointer">
                </div>
                <div class="form-group">
                    <label>Team Icon (small image)</label>
                    <input type="file" id="teamIconFile" accept="image/*" style="font-size:0.85em;color:var(--text-muted)" onchange="previewTeamIcon(this)">
                </div>
            </div>
            ${settings.teamIcon ? '<img id="teamIconPreview" src="' + settings.teamIcon + '" style="width:48px;height:48px;border-radius:10px;margin-top:8px;object-fit:cover">' : '<img id="teamIconPreview" style="display:none;width:48px;height:48px;border-radius:10px;margin-top:8px;object-fit:cover">'}
            <button class="btn btn-primary btn-sm" onclick="saveCustomization()" style="margin-top:8px">Save</button>
        </div>
        `, 'Customization')}

        <!-- Premium: Custom Roles -->
        ${premiumGate(`
        <div class="card">
            <h3>Custom Role Names</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Rename the display names for roles (permissions stay the same).</p>
            <div class="form-row" style="margin-top:8px">
                <div class="form-group">
                    <label>Leader Name</label>
                    <input type="text" id="roleLeader" placeholder="Leader" value="${settings._roleLeader || ''}">
                </div>
                <div class="form-group">
                    <label>Officer Name</label>
                    <input type="text" id="roleOfficer" placeholder="Officer" value="${settings._roleOfficer || ''}">
                </div>
                <div class="form-group">
                    <label>Member Name</label>
                    <input type="text" id="roleMember" placeholder="Member" value="${settings._roleMember || ''}">
                </div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="saveCustomRoles()" style="margin-top:8px">Save</button>
        </div>
        `, 'Custom Roles')}

        <!-- Premium: Points Decay -->
        ${premiumGate(`
        <div class="card">
            <h3>${ptsName()} Decay</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Automatically reduce ${ptsName()} for inactive members.</p>
            <label style="font-size:0.85em;color:var(--text-muted)"><input type="checkbox" id="dkpDecayEnabled" ${settings.dkpDecayEnabled ? 'checked' : ''} style="accent-color:#5865F2"> Enable ${ptsName()} Decay</label>
            <div class="form-row" style="margin-top:8px">
                <div class="form-group" style="max-width:120px">
                    <label>Decay % per cycle</label>
                    <input type="number" id="dkpDecayPercent" value="${settings.dkpDecayPercent || 10}" min="1" max="50">
                </div>
                <div class="form-group" style="max-width:150px">
                    <label>Inactive after (days)</label>
                    <input type="number" id="dkpDecayInactiveDays" value="${settings.dkpDecayInactiveDays || 14}" min="1">
                </div>
                <div class="form-group" style="max-width:150px">
                    <label>Decay every (days)</label>
                    <input type="number" id="dkpDecayIntervalDays" value="${settings.dkpDecayIntervalDays || 7}" min="1">
                </div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="saveDkpDecay()" style="margin-top:8px">Save</button>
        </div>
        `, ptsName() + ' Decay')}

        ${isLeader ? `
        <!-- Transfer Ownership -->
        <div class="card" style="border-color:#f59e0b">
            <h3 style="color:#f59e0b">Transfer Ownership</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">Transfer leader role to another member. You'll become an officer.</p>
            <div class="form-row">
                <div class="form-group" style="max-width:200px">
                    <select id="transferTarget" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                        )}'')}
                    </select>
                </div>
                <div><button class="btn" style="background:#78350f;color:#fcd34d;padding:8px 16px;font-size:0.85em" onclick="transferOwnership()">Transfer</button></div>
            </div>
        </div>

        <!-- Danger Zone -->
        <div class="card" style="border-color:#ef4444">
            <h3 style="color:#ef4444">Danger Zone</h3>
            <p style="font-size:0.8em;color:var(--text-dim);margin-bottom:8px">This cannot be undone. All team data will be permanently deleted.</p>
            <button class="btn btn-danger" onclick="deleteTeam('${currentTeamId}')">Delete Team</button>
        </div>
        ` : `
        <div class="card" style="border-color:#ef4444">
            <h3 style="color:#ef4444">Leave Team</h3>
            <button class="btn btn-danger" onclick="leaveTeam('${currentTeamId}')">Leave Team</button>
        </div>
        `}
    `;
    }

    renderTeamView();
    const el = document.getElementById('settingsContent');
    if (el) el.innerHTML = settingsContent;
    loadJoinRequests();
}

const saveWebhook = guard('saveWebhook', async function() {
    const url = document.getElementById('webhookUrl').value.trim();
    if (!url) { showToast('Paste a webhook URL first, or click Clear to remove'); return; }
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, { webhookUrl: url });
    if (res.error) { showToast(res.error); return; }
    showToast('Webhook saved');
    await renderTeamSettings();
});

const clearWebhook = guard('clearWebhook', async function() {
    if (!confirm('Remove the default webhook for this team?')) return;
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, { webhookUrl: '' });
    if (res.error) { showToast(res.error); return; }
    showToast('Webhook removed');
    await renderTeamSettings();
});

const testWebhook = guard('testWebhook', async function() {
    const data = await api('POST', `/api/teams/${currentTeamId}/settings/test`);
    showToast(data.ok ? 'Test sent!' : data.error || 'Failed');
});

async function saveNotifSettings() {
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        onWarning: document.getElementById('onWarning').checked,
        onSpawn: document.getElementById('onSpawn').checked,
        onAnnouncement: document.getElementById('onAnnouncement').checked,
        onEvent: document.getElementById('onEvent').checked,
        onWar: document.getElementById('onWar').checked,
        eventReminderMinutes: parseInt(document.getElementById('eventReminderMin').value) || 15,
    });
    if (res.error) { showToast(res.error); await renderTeamSettings(); return; }
    showToast('Notification settings saved');
}

const saveTeamInfo = guard('saveTeamInfo', async function() {
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        teamDescription: document.getElementById('teamDesc').value.trim(),
        timezone: document.getElementById('teamTimezone').value,
    });
    if (res.error) { showToast(res.error); return; }
    showToast('Team info saved');
});

const saveTeamRules = guard('saveTeamRules', async function() {
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        membersCreateEvents: document.getElementById('membersCreateEvents').checked,
        defaultEventDuration: parseInt(document.getElementById('defaultEventDuration').value) || 60,
        inactiveDays: parseInt(document.getElementById('inactiveDays').value) || 7,
        startingDkp: parseInt(document.getElementById('startingDkp').value) || 0,
        pointsName: (document.getElementById('pointsName').value.trim() || 'DKP').substring(0, 20),
    });
    if (res.error) { showToast(res.error); await renderTeamSettings(); return; }
    _pointsName = (document.getElementById('pointsName').value.trim() || 'DKP').substring(0, 20);
    showToast('Rules saved');
});

const saveInviteSettings = guard('saveInviteSettings', async function() {
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        invitesEnabled: document.getElementById('invitesEnabled').checked,
        inviteApproval: document.getElementById('inviteApproval').checked,
    });
    if (res.error) {
        showToast(res.error);
        // Revert UI to match DB state by re-rendering from fresh settings
        await renderTeamSettings();
        return;
    }
    showToast('Invite settings saved');
    loadJoinRequests();
});

async function loadJoinRequests() {
    const area = document.getElementById('joinRequestsArea');
    if (!area) return;
    const approval = document.getElementById('inviteApproval')?.checked;
    if (!approval) { area.innerHTML = ''; return; }

    const data = await api('GET', `/api/teams/${currentTeamId}/join-requests`);
    const requests = data.requests || [];
    if (requests.length === 0) {
        area.innerHTML = '<p style="color:var(--text-dim);font-size:0.85em">No pending requests.</p>';
        return;
    }
    area.innerHTML = '<p style="font-size:0.85em;color:var(--text-dim);margin-bottom:8px"><strong>' + requests.length + '</strong> pending request(s):</p>' +
        requests.map(r => `
            <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border)">
                <span style="flex:1;font-weight:500">${r.username}</span>
                <span style="font-size:0.75em;color:var(--text-dim)">${new Date(r.created_at * 1000).toLocaleDateString()}</span>
                <button class="btn btn-sm" style="background:#22c55e;color:#fff;padding:4px 10px" onclick="handleJoinRequest('${r.id}','approve')">Approve</button>
                <button class="btn btn-sm" style="background:#ef4444;color:#fff;padding:4px 10px" onclick="handleJoinRequest('${r.id}','deny')">Deny</button>
            </div>
        `).join('');
}

const handleJoinRequest = guard('handleJoinRequest', async function(reqId, action) {
    const data = await api('POST', `/api/teams/${currentTeamId}/join-requests/${reqId}/${action}`);
    if (data.error) { showToast(data.error); return; }
    showToast(data.message);
    loadJoinRequests();
    openTeam(currentTeamId);
});

const saveCleanup = guard('saveCleanup', async function() {
    await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        autoDeleteEventsDays: parseInt(document.getElementById('autoDeleteEvents').value) || 0,
        autoDeleteChatDays: parseInt(document.getElementById('autoDeleteChat').value) || 0,
    });
    showToast('Cleanup settings saved');
});

const transferOwnership = guard('transferOwnership', async function() {
    const targetId = document.getElementById('transferTarget').value;
    const targetName = document.getElementById('transferTarget').selectedOptions[0]?.text;
    if (!confirm(`Transfer ownership to ${targetName}? You'll become an officer.`)) return;
    const data = await api('POST', `/api/teams/${currentTeamId}/transfer`, { userId: targetId });
    if (data.error) { showToast(data.error); return; }
    showToast('Ownership transferred!');
    openTeam(currentTeamId);
});

// Premium settings save functions
const saveChannelWebhooks = guard('saveChannelWebhooks', async function() {
    // Only send fields the user actually typed into — empty inputs mean "don't touch".
    const body = {};
    const boss = document.getElementById('webhookBoss').value.trim();
    const events = document.getElementById('webhookEvents').value.trim();
    const wars = document.getElementById('webhookWars').value.trim();
    const ann = document.getElementById('webhookAnnouncements').value.trim();
    if (boss) body.webhookBoss = boss;
    if (events) body.webhookEvents = events;
    if (wars) body.webhookWars = wars;
    if (ann) body.webhookAnnouncements = ann;
    if (Object.keys(body).length === 0) { showToast('Nothing to save — paste a webhook URL first'); return; }
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, body);
    if (res.error) { showToast(res.error); return; }
    showToast('Channel webhooks saved');
    await renderTeamSettings();
});

const clearChannelWebhook = guard('clearChannelWebhook', async function(which) {
    if (!confirm(`Clear the ${which} webhook override?`)) return;
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, { ['webhook' + which]: '' });
    if (res.error) { showToast(res.error); return; }
    showToast(`${which} webhook cleared`);
    await renderTeamSettings();
});

function previewTeamIcon(input) {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 50000) { showToast('Image must be under 50KB'); input.value = ''; return; }
    const reader = new FileReader();
    reader.onload = function(e) {
        const img = document.getElementById('teamIconPreview');
        img.src = e.target.result;
        img.style.display = 'block';
    };
    reader.readAsDataURL(file);
}

const saveCustomization = guard('saveCustomization', async function() {
    const accentColor = document.getElementById('accentColor').value;
    const iconImg = document.getElementById('teamIconPreview');
    const teamIcon = iconImg.src && iconImg.src.startsWith('data:') ? iconImg.src : '';
    const data = await api('PUT', `/api/teams/${currentTeamId}/settings`, { accentColor, teamIcon });
    if (data.error) { showToast(data.error); return; }
    showToast('Customization saved');
    if (accentColor) document.documentElement.style.setProperty('--accent', accentColor);
});

const saveCustomRoles = guard('saveCustomRoles', async function() {
    await api('PUT', `/api/teams/${currentTeamId}/roles`, {
        roles: {
            leader: { displayName: document.getElementById('roleLeader').value.trim() },
            officer: { displayName: document.getElementById('roleOfficer').value.trim() },
            member: { displayName: document.getElementById('roleMember').value.trim() },
        }
    });
    showToast('Custom roles saved');
});

const saveDkpDecay = guard('saveDkpDecay', async function() {
    await api('PUT', `/api/teams/${currentTeamId}/settings`, {
        dkpDecayEnabled: document.getElementById('dkpDecayEnabled').checked,
        dkpDecayPercent: parseInt(document.getElementById('dkpDecayPercent').value) || 10,
        dkpDecayInactiveDays: parseInt(document.getElementById('dkpDecayInactiveDays').value) || 14,
        dkpDecayIntervalDays: parseInt(document.getElementById('dkpDecayIntervalDays').value) || 7,
    });
    showToast(ptsName() + ' decay settings saved');
});

const savePublicTimers = guard('savePublicTimers', async function() {
    const on = document.getElementById('publicTimers').checked;
    const res = await api('PUT', `/api/teams/${currentTeamId}/settings`, { publicTimers: on });
    if (res.error) { showToast(res.error); return; }
    showToast(on ? 'Public timer page enabled' : 'Public timer page disabled');
    await renderTeamSettings();
});

function copyPublicTimersUrl() {
    navigator.clipboard.writeText(document.getElementById('publicTimersUrl').textContent);
    showToast('Link copied');
}
