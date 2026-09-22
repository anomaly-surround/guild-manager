// DKP points tab + auctions

// --- DKP Points ---

let dkpShowHistory = false;

async function loadAndRenderDKP() {
    teamTab = 'dkp';
    renderTeamView();
    const [balData, histData] = await Promise.all([
        api('GET', `/api/teams/${currentTeamId}/dkp`),
        api('GET', `/api/teams/${currentTeamId}/dkp/history`),
    ]);
    const el = document.getElementById('dkpContent');
    if (el) el.innerHTML = renderDKPContent(balData.balances || [], histData.history || []) + '<div id="auctionsArea"></div>';
    // Load auctions async (premium)
    if (teamData?.team?.premium_team) {
        const ahtml = await renderAuctionsSection();
        const aa = document.getElementById('auctionsArea');
        if (aa) aa.innerHTML = ahtml;
    }
}

function renderDKPContent(balances, history) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    const members = teamData.members || [];
    let html = '';

    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addDkpForm', this)">
                    <h3>+ Award / Deduct ${ptsName()}</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addDkpForm">
                    <div class="form-row" style="margin-top:12px">
                        <div class="form-group">
                            <label>Member</label>
                            <select id="dkpMember" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                <option value="__all__">All Members</option>
                                ${members.map(m => `<option value="${m.id}">${escapeHtml(m.username)}</option>`).join('')}
                            </select>
                        </div>
                        <div class="form-group" style="max-width:100px">
                            <label>Amount</label>
                            <input type="number" id="dkpAmount" placeholder="e.g. 10">
                        </div>
                    </div>
                    <div class="form-group" style="margin-top:8px">
                        <label>Reason</label>
                        <input type="text" id="dkpReason" placeholder="e.g. Raid attendance, boss kill">
                    </div>
                    <div style="margin-top:10px">
                        <button class="btn btn-primary" onclick="awardDKP()">Submit</button>
                        <span style="font-size:0.8em;color:#64748b;margin-left:8px">Use negative for deductions</span>
                    </div>
                </div>
            </div>
        `;
    }

    // Leaderboard
    html += '<div class="card"><h3>' + ptsName() + ' Standings</h3>';
    if (balances.length === 0) {
        html += '<div class="empty-state">No ' + ptsName() + ' recorded yet</div>';
    } else {
        for (let i = 0; i < balances.length; i++) {
            const b = balances[i];
            const medal = i === 0 ? '&#129351; ' : i === 1 ? '&#129352; ' : i === 2 ? '&#129353; ' : '';
            html += `
                <div class="dkp-row">
                    <div>
                        <span>${medal}${escapeHtml(b.username)}</span>
                    </div>
                    <span class="${b.balance >= 0 ? 'dkp-positive' : 'dkp-negative'}">${b.balance >= 0 ? '+' : ''}${b.balance} ${ptsName()}</span>
                </div>
            `;
        }
    }
    html += '</div>';

    // History toggle
    html += `<div class="card"><h3 style="cursor:pointer" onclick="document.getElementById('dkpHistoryList').style.display=document.getElementById('dkpHistoryList').style.display==='none'?'block':'none'">History &#9660;</h3>`;
    html += '<div id="dkpHistoryList" style="display:none">';
    if (history.length === 0) {
        html += '<div class="empty-state">No history</div>';
    } else {
        for (const h of history) {
            const date = new Date(h.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            html += `
                <div class="dkp-row">
                    <div>
                        <span style="font-weight:600">${escapeHtml(h.username)}</span>
                        <span style="font-size:0.8em;color:#64748b"> &middot; ${escapeHtml(h.reason)} &middot; by ${escapeHtml(h.created_by_name)} &middot; ${date}</span>
                    </div>
                    <span class="${h.amount >= 0 ? 'dkp-positive' : 'dkp-negative'}">${h.amount >= 0 ? '+' : ''}${h.amount}</span>
                </div>
            `;
        }
    }
    html += '</div></div>';

    return html;
}

const awardDKP = guard('awardDKP', async function() {
    const memberId = document.getElementById('dkpMember').value;
    const amount = parseInt(document.getElementById('dkpAmount').value);
    const reason = document.getElementById('dkpReason').value.trim();
    if (!amount || !reason) return showToast('Amount and reason required');

    if (memberId === '__all__') {
        const userIds = teamData.members.map(m => m.id);
        const data = await api('POST', `/api/teams/${currentTeamId}/dkp/bulk`, { userIds, amount, reason });
        if (data.error) { showToast(data.error); return; }
        showToast(`${ptsName()} awarded to all members!`);
    } else {
        const data = await api('POST', `/api/teams/${currentTeamId}/dkp`, { userId: memberId, amount, reason });
        if (data.error) { showToast(data.error); return; }
        showToast(ptsName() + ' updated!');
    }
    loadAndRenderDKP();
});

// --- Premium: DKP Auctions ---

async function renderAuctionsSection() {
    if (!teamData?.team?.premium_team) return '';
    const data = await api('GET', `/api/teams/${currentTeamId}/auctions`);
    const auctions = data.auctions || [];
    const canManage = teamData.team.my_role !== 'member';

    let html = '<div class="card"><h3>' + ptsName() + ' Auctions</h3>';
    if (canManage) {
        html += `<div class="form-row" style="margin-bottom:8px">
            <div class="form-group"><input type="text" id="auctionItem" placeholder="Item name"></div>
            <div class="form-group" style="max-width:100px"><input type="number" id="auctionMinBid" placeholder="Min bid" value="0" min="0"></div>
            <div><button class="btn btn-primary btn-sm" onclick="createAuction()">Start Auction</button></div>
        </div>`;
    }

    const open = auctions.filter(a => a.status === 'open');
    const closed = auctions.filter(a => a.status === 'closed');

    if (open.length > 0) {
        html += '<h4 style="color:var(--text-muted);font-size:0.85em;margin:8px 0">Active</h4>';
        for (const a of open) {
            html += `<div class="dkp-row" style="flex-wrap:wrap">
                <div><span class="loot-item-name">${escapeHtml(a.item_name)}</span> <span style="font-size:0.8em;color:var(--text-dim)">by ${escapeHtml(a.started_by_name)} &middot; ${a.bid_count} bids</span></div>
                <div style="display:flex;gap:6px;align-items:center">
                    <span style="font-weight:600;color:#34d399">${a.top_bid || a.min_bid || 0} ${ptsName()}</span>
                    <input type="number" id="bid_${a.id}" placeholder="Your bid" min="${(a.top_bid || a.min_bid || 0) + 1}" style="width:80px;background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:6px;border-radius:6px;font-size:0.85em">
                    <button class="btn btn-primary btn-sm" onclick="placeBid('${a.id}')" style="font-size:0.75em">Bid</button>
                    ${canManage ? `<button class="btn btn-secondary btn-sm" onclick="closeAuction('${a.id}')" style="font-size:0.75em">Close</button>` : ''}
                </div>
            </div>`;
        }
    }

    if (closed.length > 0) {
        html += '<h4 style="color:var(--text-muted);font-size:0.85em;margin:8px 0">Closed</h4>';
        for (const a of closed.slice(0, 10)) {
            html += `<div class="dkp-row" style="opacity:0.6">
                <span>${escapeHtml(a.item_name)}</span>
                <span style="font-size:0.85em">${a.winner_name ? `Won by ${escapeHtml(a.winner_name)} for ${a.winning_bid} ${ptsName()}` : 'No bids'}</span>
            </div>`;
        }
    }

    if (auctions.length === 0) html += '<div class="empty-state">No auctions yet</div>';
    html += '</div>';
    return html;
}

const createAuction = guard('createAuction', async function() {
    const itemName = document.getElementById('auctionItem').value.trim();
    if (!itemName) return showToast('Item name required');
    await api('POST', `/api/teams/${currentTeamId}/auctions`, {
        itemName, minBid: parseInt(document.getElementById('auctionMinBid').value) || 0
    });
    showToast('Auction started!');
    loadAndRenderDKP();
});

const placeBid = guard('placeBid', async function(auctionId) {
    const amount = parseInt(document.getElementById('bid_' + auctionId).value);
    if (!amount) return showToast('Enter a bid amount');
    const data = await api('POST', `/api/teams/${currentTeamId}/auctions/${auctionId}/bid`, { amount });
    if (data.error) { showToast(data.error); return; }
    showToast('Bid placed!');
    loadAndRenderDKP();
});

const closeAuction = guard('closeAuction', async function(auctionId) {
    if (!confirm('Close this auction? Winner will be charged.')) return;
    await api('POST', `/api/teams/${currentTeamId}/auctions/${auctionId}/close`);
    showToast('Auction closed');
    loadAndRenderDKP();
});
