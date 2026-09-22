// Loot tracker tab + wishlist

// --- Loot Tracker ---

async function loadAndRenderLoot() {
    teamTab = 'loot';
    renderTeamView();
    const data = await api('GET', `/api/teams/${currentTeamId}/loot`);
    const el = document.getElementById('lootContent');
    if (el) el.innerHTML = renderLootContent(data.loot || []) + '<div id="wishlistArea"></div>';
    // Load wishlist async (premium)
    if (teamData?.team?.premium_team) {
        const whtml = await renderWishlistSection();
        const wa = document.getElementById('wishlistArea');
        if (wa) wa.innerHTML = whtml;
    }
}

function renderLootContent(loot) {
    const team = teamData.team;
    const canManage = team.my_role === 'leader' || team.my_role === 'officer';
    const members = teamData.members || [];
    let html = '';

    if (canManage) {
        html += `
            <div class="card">
                <div class="collapsible-header" onclick="toggleSection('addLootForm', this)">
                    <h3>+ Log Loot Drop</h3>
                    <span class="toggle-arrow">&#9660;</span>
                </div>
                <div class="collapsible-body" id="addLootForm">
                    <div class="form-row" style="margin-top:12px">
                        <div class="form-group">
                            <label>Item Name</label>
                            <input type="text" id="lootItemName" placeholder="e.g. Dragon Sword">
                        </div>
                        <div class="form-group">
                            <label>Boss Name</label>
                            <input type="text" id="lootBossName" placeholder="e.g. Dragon Lord">
                        </div>
                    </div>
                    <div class="form-row" style="margin-top:8px">
                        <div class="form-group">
                            <label>Received By</label>
                            <select id="lootRecipient" style="background:#1e293b;border:1px solid #334155;color:#e0e6f0;padding:10px;border-radius:8px">
                                ${members.map(m => `<option value="${m.id}">${escapeHtml(m.username)}</option>`).join('')}
                            </select>
                        </div>
                        <div class="form-group" style="max-width:100px">
                            <label>${ptsName()} Cost</label>
                            <input type="number" id="lootDkpCost" value="0" min="0">
                        </div>
                        <div style="align-self:flex-end"><button class="btn btn-primary" onclick="addLoot()">Log</button></div>
                    </div>
                </div>
            </div>
        `;
    }

    if (loot.length === 0) {
        html += '<div class="empty-state">No loot logged yet</div>';
    } else {
        for (const l of loot) {
            const date = new Date(l.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
            html += `
                <div class="loot-item">
                    <div>
                        <span class="loot-item-name">${escapeHtml(l.item_name)}</span>
                        <span style="color:#64748b;font-size:0.8em"> from ${escapeHtml(l.boss_name)}</span>
                        <div style="font-size:0.8em;color:#94a3b8">${escapeHtml(l.recipient_name)} ${l.dkp_cost ? `(-${l.dkp_cost} ${ptsName()})` : ''} &middot; ${date}</div>
                    </div>
                    ${canManage ? `<button class="btn btn-danger btn-sm" onclick="deleteLoot('${l.id}')" style="font-size:0.7em;padding:2px 8px">X</button>` : ''}
                </div>
            `;
        }
    }
    return html;
}

const addLoot = guard('addLoot', async function() {
    const itemName = document.getElementById('lootItemName').value.trim();
    const bossName = document.getElementById('lootBossName').value.trim();
    const recipientId = document.getElementById('lootRecipient').value;
    const dkpCost = parseInt(document.getElementById('lootDkpCost').value) || 0;
    if (!itemName) return showToast('Item name required');
    const data = await api('POST', `/api/teams/${currentTeamId}/loot`, { itemName, bossName: bossName || 'Unknown', recipientId, dkpCost });
    if (data.error) { showToast(data.error); return; }
    showToast('Loot logged!');
    loadAndRenderLoot();
});

const deleteLoot = guard('deleteLoot', async function(id) {
    await api('DELETE', `/api/teams/${currentTeamId}/loot/${id}`);
    loadAndRenderLoot();
});

// --- Premium: Wishlist (in Loot tab) ---

async function renderWishlistSection() {
    if (!teamData?.team?.premium_team) return '';
    const data = await api('GET', `/api/teams/${currentTeamId}/wishlist`);
    const wishes = data.wishes || [];
    const canManage = teamData.team.my_role !== 'member';
    const priorities = ['', 'Low', 'Med', 'High'];

    let html = '<div class="card"><h3>Loot Wishlist</h3>';
    html += `<div class="form-row" style="margin-bottom:8px">
        <div class="form-group"><input type="text" id="wishItem" placeholder="Item name"></div>
        <div class="form-group" style="max-width:120px"><input type="text" id="wishBoss" placeholder="Boss (opt)"></div>
        <div class="form-group" style="max-width:80px">
            <select id="wishPriority" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px;border-radius:8px">
                <option value="1">Low</option><option value="2">Med</option><option value="3">High</option>
            </select>
        </div>
        <div><button class="btn btn-primary btn-sm" onclick="addWish()">Add</button></div>
    </div>`;

    if (wishes.length === 0) {
        html += '<div class="empty-state">No wishes yet</div>';
    } else {
        for (const w of wishes) {
            html += `<div class="loot-item"><div>
                <span style="font-weight:600">${escapeHtml(w.item_name)}</span>
                ${w.boss_name ? `<span style="color:var(--text-dim);font-size:0.8em"> from ${escapeHtml(w.boss_name)}</span>` : ''}
                <div style="font-size:0.75em;color:var(--text-muted)">${escapeHtml(w.username)} &middot; Priority: ${priorities[w.priority] || 'Low'}</div>
            </div>
            <button class="btn btn-danger btn-sm" onclick="deleteWish('${w.id}')" style="font-size:0.7em;padding:2px 8px">X</button>
            </div>`;
        }
    }
    html += '</div>';
    return html;
}

const addWish = guard('addWish', async function() {
    const itemName = document.getElementById('wishItem').value.trim();
    if (!itemName) return showToast('Item name required');
    await api('POST', `/api/teams/${currentTeamId}/wishlist`, {
        itemName,
        bossName: document.getElementById('wishBoss').value.trim() || null,
        priority: parseInt(document.getElementById('wishPriority').value) || 1,
    });
    showToast('Added to wishlist');
    loadAndRenderLoot();
});

const deleteWish = guard('deleteWish', async function(id) {
    await api('DELETE', `/api/teams/${currentTeamId}/wishlist/${id}`);
    loadAndRenderLoot();
});
