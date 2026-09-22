// Premium upgrade modal, free trial, Paddle checkout

function showUpgradeModal() {
    const isGuest = currentUser?.authType === 'guest';
    const trialUsed = currentUser?.trialUsed || isGuest;
    const trialBtn = trialUsed ? (isGuest ? `
        <div style="margin-bottom:14px;padding:12px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:8px;text-align:center">
            <p style="color:#f59e0b;font-size:0.85em">Sign in with Discord or Google to start a free trial.</p>
        </div>` : '') : `
        <div style="margin-bottom:14px;padding:12px;background:rgba(52,211,153,0.1);border:1px solid rgba(52,211,153,0.3);border-radius:8px;text-align:center">
            <p style="color:#34d399;font-size:0.9em;font-weight:600;margin-bottom:8px">Try Premium free for 7 days!</p>
            <button class="btn" style="background:#065f46;color:#34d399;padding:8px 20px;font-size:0.9em" onclick="startFreeTrial()">Start Free Trial</button>
            <p style="color:var(--text-dim);font-size:0.75em;margin-top:6px">No payment required. One trial per account.</p>
        </div>`;
    document.getElementById('deathModal').innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:100" onclick="if(event.target===this)document.getElementById('deathModal').innerHTML=''">
            <div class="card" style="width:420px;max-width:90vw;margin:0;border-color:#7c3aed;">
                <h2 style="color:#a78bfa">Upgrade to Premium</h2>
                <p style="color:var(--text-muted);font-size:0.9em;margin-bottom:6px">Free covers 1 team, 10 members and 15 timers. Premium adds:</p>
                <ul style="margin:0 0 14px 18px;color:var(--text-muted);font-size:0.85em;line-height:1.6">
                    <li>Unlimited teams and timers, up to 100 members</li>
                    <li>Public timer page to pin in Discord</li>
                    <li>Per-channel Discord webhooks</li>
                    <li>Boss templates and kill history</li>
                    <li>Event templates, attendance report, calendar feed</li>
                    <li>Loot wishlist, points auctions and decay</li>
                </ul>
                ${trialBtn}
                <div style="display:flex;gap:10px;">
                    <button class="btn btn-primary" onclick="checkout('monthly')">Monthly Plan</button>
                    <button class="btn btn-primary" onclick="checkout('lifetime')">Lifetime (one-time)</button>
                </div>
                <button class="btn" style="margin-top:12px;background:var(--bg-input);color:var(--text);" onclick="document.getElementById('deathModal').innerHTML=''">Cancel</button>
            </div>
        </div>`;
}

const startFreeTrial = guard('startFreeTrial', async function() {
    const data = await api('POST', '/api/start-trial');
    if (data.error) { showToast(data.error); return; }
    document.getElementById('deathModal').innerHTML = '';
    showToast('Free trial started! You have 7 days of Premium.');
    // Refresh user data
    const user = await api('GET', '/auth/me');
    if (user && !user.error) {
        currentUser = user;
        showUserInfo();
    }
    if (currentTeamId) openTeam(currentTeamId);
});

// --- Actions ---

const checkout = guard('checkout', async function(type) {
    const data = await api('POST', '/api/checkout', { type });
    if (data.error) { showToast(data.error); return; }
    if (!data.priceId) { showToast('Failed to create checkout'); return; }

    document.getElementById('deathModal').innerHTML = '';
    Paddle.Checkout.open({
        items: [{ priceId: data.priceId, quantity: 1 }],
        customData: { user_id: data.userId },
        successCallback: async () => {
            showToast('Payment successful! Activating premium...');
            // Wait a moment for webhook to process
            setTimeout(async () => {
                const user = await api('GET', '/auth/me');
                if (user && !user.error) { currentUser = user; showUserInfo(); }
                if (currentTeamId) openTeam(currentTeamId);
            }, 3000);
        },
        closeCallback: () => {},
    });
});
