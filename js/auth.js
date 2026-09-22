// OAuth token landing, init(), login screen, user header, login/logout actions

// --- Init ---

// Check for token in URL (from OAuth redirect)
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.get('token')) {
    token = urlParams.get('token');
    localStorage.setItem('gm_token', token);
    window.history.replaceState({}, '', window.location.pathname);
}

// init() is called after the api() cache block below is set up (const/TDZ).

async function init() {
    if (!token) {
        showLogin();
        return;
    }
    let user = await api('GET', '/auth/me');
    // Retry once on failure (cold start)
    if (!user || user.error) {
        await new Promise(r => setTimeout(r, 1500));
        user = await api('GET', '/auth/me');
    }
    if (!user || user.error) {
        _clearApiCache();
        localStorage.removeItem('gm_token');
        token = '';
        showLogin();
        return;
    }
    currentUser = user;
    showUserInfo();
    showTeamList();
}

// --- Views ---

function showLogin() {
    document.getElementById('mainContent').innerHTML = `
        <div class="login-screen">
            <h2>Guild Manager</h2>
            <p style="padding:0 16px">Manage your gaming team, track boss spawns, schedule events</p>
            <div style="display:flex;flex-direction:column;gap:10px;width:280px;max-width:90vw">
                <button class="btn btn-discord" onclick="login()" style="justify-content:center">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03z"/></svg>
                    Login with Discord
                </button>
                <button class="btn" onclick="loginGoogle()" style="background:#fff;color:#333;font-size:1em;padding:12px 24px;display:flex;align-items:center;gap:8px;justify-content:center;font-weight:600">
                    <svg width="20" height="20" viewBox="0 0 48 48"><path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/><path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"/><path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0124 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/><path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 01-4.087 5.571l.003-.002 6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/></svg>
                    Login with Google
                </button>
                <div style="display:flex;align-items:center;gap:10px;margin:4px 0">
                    <div style="flex:1;height:1px;background:var(--border)"></div>
                    <span style="color:var(--text-dim);font-size:0.8em">or</span>
                    <div style="flex:1;height:1px;background:var(--border)"></div>
                </div>
                <div style="display:flex;flex-direction:column;gap:8px">
                    <input type="text" id="guestName" placeholder="Enter a username" style="background:var(--bg-input);border:1px solid var(--border-input);color:var(--text);padding:10px 14px;border-radius:8px;font-size:0.9em;width:100%" maxlength="20" onkeydown="if(event.key==='Enter')loginGuest()">
                    <button class="btn btn-secondary" onclick="loginGuest()" style="width:100%;padding:12px">Join as Guest</button>
                </div>
                <p style="color:var(--text-dim);font-size:0.7em;text-align:center">Guest accounts have limited features. Sign in with Discord or Google for the full experience.</p>
            </div>
        </div>
    `;
}

function showUserInfo() {
    const el = document.getElementById('userInfo');
    el.style.display = 'flex';
    document.getElementById('headerActions').style.display = 'flex';
    document.getElementById('userName').textContent = currentUser.username +
        (currentUser.trial ? ' (Trial)' : currentUser.premium ? ' (Premium)' : '');
    if (currentUser.avatar) {
        document.getElementById('userAvatar').src =
            `https://cdn.discordapp.com/avatars/${currentUser.discordId}/${currentUser.avatar}.png?size=64`;
    }
    const upgradeBtn = document.getElementById('upgradeBtn');
    if (currentUser.trial) {
        upgradeBtn.style.display = 'inline-block';
        upgradeBtn.textContent = `Trial: ${currentUser.trialDaysLeft}d left`;
        upgradeBtn.style.background = 'linear-gradient(135deg,#065f46,#059669)';
        upgradeBtn.onclick = showUpgradeModal;
    } else if (currentUser.premium) {
        upgradeBtn.style.display = 'none';
    } else {
        upgradeBtn.style.display = 'inline-block';
        upgradeBtn.textContent = 'Upgrade';
        upgradeBtn.style.background = 'linear-gradient(135deg,#7c3aed,#6d28d9)';
    }
}

function login() {
    window.location.href = API + '/auth/login';
}

function loginGoogle() {
    window.location.href = API + '/auth/google';
}

const loginGuest = guard('loginGuest', async function() {
    const username = document.getElementById('guestName').value.trim();
    if (!username || username.length < 2) return showToast('Username must be at least 2 characters');
    const data = await api('POST', '/auth/guest', { username });
    if (data.error) { showToast(data.error); return; }
    token = data.token;
    localStorage.setItem('gm_token', token);
    init();
});

function logout() {
    _clearApiCache();
    localStorage.removeItem('gm_token');
    token = '';
    currentUser = null;
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('headerActions').style.display = 'none';
    showLogin();
}
