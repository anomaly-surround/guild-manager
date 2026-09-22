// Team chat + reactions

// --- Chat ---

let chatMessages = [];
let chatLastTimestamp = 0;

async function loadAndRenderChat() {
    teamTab = 'chat';
    chatMessages = [];
    chatLastTimestamp = 0;
    renderTeamView();
    await fetchChatMessages(true);
}

async function fetchChatMessages(fullLoad) {
    const after = fullLoad ? '0' : String(chatLastTimestamp);
    const data = await api('GET', `/api/teams/${currentTeamId}/chat?after=${after}`);
    const newMsgs = data.messages || [];
    if (newMsgs.length > 0) {
        if (fullLoad) {
            chatMessages = newMsgs;
        } else {
            const existingIds = new Set(chatMessages.map(m => m.id));
            const unique = newMsgs.filter(m => !existingIds.has(m.id));
            if (unique.length > 0) chatMessages = chatMessages.concat(unique);
        }
        chatLastTimestamp = newMsgs[newMsgs.length - 1].created_at;
    }

    if (fullLoad) {
        // Full render on first load
        const el = document.getElementById('chatContent');
        if (el) el.innerHTML = renderChatContent();
        const msgBox = document.getElementById('chatMsgBox');
        if (msgBox) msgBox.scrollTop = msgBox.scrollHeight;
    } else if (newMsgs.length > 0) {
        // Only update the messages area, preserve input
        const msgBox = document.getElementById('chatMsgBox');
        if (msgBox) {
            const wasAtBottom = msgBox.scrollHeight - msgBox.scrollTop - msgBox.clientHeight < 50;
            msgBox.innerHTML = renderChatMessages();
            if (wasAtBottom) msgBox.scrollTop = msgBox.scrollHeight;
        }
    }
}

function renderChatMessages() {
    const canManage = teamData.team.my_role === 'leader' || teamData.team.my_role === 'officer';
    if (chatMessages.length === 0) {
        return '<div class="empty-state" style="margin:auto">No messages yet. Say hi!</div>';
    }
    let html = '';
    for (const m of chatMessages) {
        const avatarUrl = m.avatar ? `https://cdn.discordapp.com/avatars/${m.discord_id}/${m.avatar}.png?size=64` : '';
        const time = new Date(m.created_at * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        const date = new Date(m.created_at * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        const canDelete = m.user_id === currentUser.id || canManage;
        html += `
            <div class="chat-msg">
                <img class="chat-msg-avatar" src="${avatarUrl}" onerror="this.style.background='#334155'">
                <div class="chat-msg-body">
                    <span class="chat-msg-name">${escapeHtml(m.username)}</span>
                    <span class="chat-msg-time">${date} ${time}</span>
                    ${canDelete ? `<span class="chat-msg-time" style="cursor:pointer;color:#ef4444" onclick="deleteChat('${m.id}')">[x]</span>` : ''}
                    <div class="chat-msg-text">${escapeHtml(m.message)}</div>
                    ${renderReactions(m.id, m.reactions)}
                </div>
            </div>
        `;
    }
    return html;
}

function renderChatContent() {
    return `
        <div class="chat-container">
            <div class="chat-messages" id="chatMsgBox">${renderChatMessages()}</div>
            <div class="chat-input-bar">
                <input type="text" id="chatInput" placeholder="Type a message..." onkeydown="if(event.key==='Enter')sendChat()" maxlength="2000">
                <button class="btn btn-primary" onclick="sendChat()">Send</button>
            </div>
        </div>
    `;
}

let chatSending = false;
async function sendChat() {
    if (chatSending) return;
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    if (!message) return;
    chatSending = true;
    input.value = '';
    input.disabled = true;
    try {
        const data = await api('POST', `/api/teams/${currentTeamId}/chat`, { message });
        if (data.error) { showToast(data.error); return; }
        await fetchChatMessages(false);
    } finally {
        chatSending = false;
        const inp = document.getElementById('chatInput');
        if (inp) { inp.disabled = false; inp.focus(); }
    }
}

async function deleteChat(id) {
    await api('DELETE', `/api/teams/${currentTeamId}/chat/${id}`);
    chatMessages = chatMessages.filter(m => m.id !== id);
    const msgBox = document.getElementById('chatMsgBox');
    if (msgBox) msgBox.innerHTML = renderChatMessages();
}

// --- Premium: Chat Reactions ---

const commonEmoji = ['👍','👎','❤️','😂','😮','🔥','🎉','💀','⚔️','🛡️'];

function renderReactions(msgId, reactions) {
    if (!teamData?.team?.premium_team) return '';
    const grouped = {};
    for (const r of (reactions || [])) {
        if (!grouped[r.emoji]) grouped[r.emoji] = { count: 0, mine: false };
        grouped[r.emoji].count++;
        if (r.user_id === currentUser.id) grouped[r.emoji].mine = true;
    }
    let html = '<div style="display:flex;gap:3px;margin-top:4px;flex-wrap:wrap">';
    for (const [emoji, data] of Object.entries(grouped)) {
        html += `<span onclick="reactToMsg('${msgId}','${emoji}')" style="cursor:pointer;font-size:0.75em;padding:1px 5px;border-radius:10px;background:${data.mine ? 'var(--accent)' : 'var(--bg-input)'};border:1px solid var(--border)">${emoji} ${data.count}</span>`;
    }
    html += `<span onclick="showEmojiPicker('${msgId}')" style="cursor:pointer;font-size:0.75em;padding:1px 5px;border-radius:10px;background:var(--bg-input);border:1px solid var(--border)">+</span>`;
    html += '</div>';
    return html;
}

function showEmojiPicker(msgId) {
    const existing = document.getElementById('emojiPicker');
    if (existing) existing.remove();
    const el = document.createElement('div');
    el.id = 'emojiPicker';
    el.style.cssText = 'position:fixed;bottom:80px;right:20px;background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:8px;display:flex;flex-wrap:wrap;gap:4px;max-width:200px;z-index:200';
    el.innerHTML = commonEmoji.map(e => `<span onclick="reactToMsg('${msgId}','${e}');document.getElementById('emojiPicker').remove()" style="cursor:pointer;font-size:1.2em;padding:4px">${e}</span>`).join('');
    el.innerHTML += `<span onclick="this.parentElement.remove()" style="cursor:pointer;font-size:0.8em;padding:4px;color:var(--text-dim)">Close</span>`;
    document.body.appendChild(el);
}

const reactToMsg = guard('reactToMsg', async function(msgId, emoji) {
    await api('POST', `/api/teams/${currentTeamId}/chat/${msgId}/react`, { emoji });
    await fetchChatMessages(true);
});
