// Account & data modal: export my data (JSON download), delete my account

function showAccountModal() {
    const host = document.getElementById('deathModal');
    const method = { discord: 'Discord', google: 'Google', guest: 'Guest (this browser only)' }[currentUser?.authType] || currentUser?.authType || '';
    const plan = currentUser?.trial ? `Trial, ${currentUser.trialDaysLeft} days left` : currentUser?.premium ? (currentUser.premiumType === 'lifetime' ? 'Lifetime Premium' : 'Premium') : 'Free';
    host.innerHTML = `
        <div class="modal-backdrop">
            <div class="card modal-card">
                <div class="help-head"><h2>Account &amp; data</h2><button class="tbtn-icon" data-close title="Close">&#10005;</button></div>
                <div class="acct-facts">
                    <div><span>Name</span><b>${escapeHtml(currentUser?.username || '')}</b></div>
                    <div><span>Signed in with</span><b>${escapeHtml(method)}</b></div>
                    <div><span>Plan</span><b>${escapeHtml(plan)}</b></div>
                </div>

                <h3 class="t-h3">Export</h3>
                <p class="tf-help">A JSON file with your profile, your memberships, and the full data of every team you lead (members, timers, events, loot, points).</p>
                <div class="tf-actions" style="justify-content:flex-start"><button class="btn btn-secondary btn-sm" data-act="export">Download my data</button></div>

                <h3 class="t-h3">Delete account</h3>
                <p class="tf-help">Removes your sign-in, avatar, memberships, RSVPs, availability, wishlists and any notes about you. Teams you lead alone are deleted with you. Teams you lead that have other members must be transferred or deleted first. Team histories keep entries you created as "Deleted user". This cannot be undone.</p>
                <div class="acct-teams" data-role="teams"></div>
                <form class="acct-delete" data-act="delete">
                    <input type="text" data-role="confirm" placeholder="Type DELETE to confirm" autocomplete="off" spellcheck="false">
                    <button class="btn btn-danger" type="submit" disabled>Delete my account</button>
                </form>
                <div class="bill-status" data-role="status"></div>
            </div>
        </div>`;

    const back = host.firstElementChild;
    const status = (html, kind) => { const el = back.querySelector('[data-role="status"]'); el.innerHTML = html ? `<div class="bill-note bill-note-${kind || 'muted'}">${html}</div>` : ''; };
    const confirmInput = back.querySelector('[data-role="confirm"]');
    const deleteBtn = back.querySelector('form[data-act="delete"] button');
    confirmInput.addEventListener('input', () => { deleteBtn.disabled = confirmInput.value.trim() !== 'DELETE'; });

    // Teams you lead, so the rule above is concrete before the user types DELETE.
    api('GET', '/api/teams').then(d => {
        const led = (d.teams || []).filter(t => t.role === 'leader');
        const el = back.querySelector('[data-role="teams"]');
        if (!led.length) { el.innerHTML = ''; return; }
        el.innerHTML = `<div class="acct-teamlist">${led.map(t => `<div class="t-row t-row-sm"><span>${escapeHtml(t.name)}</span><span class="t-dim">${t.member_count} member${t.member_count === 1 ? '' : 's'} · ${t.member_count > 1 ? 'transfer or delete first' : 'will be deleted with you'}</span></div>`).join('')}</div>`;
    });

    back.addEventListener('click', (e) => {
        if (e.target === back || e.target.closest('[data-close]')) { host.innerHTML = ''; return; }
        if (e.target.closest('[data-act="export"]')) exportMyData(status);
    });
    back.querySelector('form[data-act="delete"]').addEventListener('submit', (e) => { e.preventDefault(); deleteMyAccount(status); });
}

const exportMyData = guard('exportMyData', async function(status) {
    status('Preparing your export&hellip;', 'muted');
    try {
        const res = await fetch(`${API}/api/me/export`, { headers: { Authorization: `Bearer ${token}` } });
        if (!res.ok) { const d = await res.json().catch(() => ({})); status(d.error || 'Export failed', 'warn'); return; }
        const blob = await res.blob();
        const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: 'guild-manager-export.json' });
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 10000);
        status('Downloaded <b>guild-manager-export.json</b>.', 'success');
    } catch (e) {
        status('Export failed: network error', 'warn');
    }
});

const deleteMyAccount = guard('deleteMyAccount', async function(status) {
    status('Deleting&hellip;', 'muted');
    const d = await api('DELETE', '/api/me');
    if (d.error) {
        const list = (d.teams || []).map(t => `<b>${escapeHtml(t.name)}</b> (${t.members} members)`).join(', ');
        status(escapeHtml(d.error) + (list ? `<br>${list}` : ''), 'warn');
        return;
    }
    document.getElementById('deathModal').innerHTML = '';
    showToast('Your account has been deleted.');
    logout();
});
