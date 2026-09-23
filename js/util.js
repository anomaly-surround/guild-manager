// Generic helpers: escapeHtml, formatTime, formatTimeLong, showToast, copyInvite, goHome

// Modal backdrops close on a click OUTSIDE the card. A drag that starts inside the card (selecting
// text in a field) and ends on the backdrop also fires a 'click' on the backdrop; swallow those so
// every module's "click backdrop = close" handler only sees real outside clicks.
(function() {
    let pressedOnBackdrop = false;
    document.addEventListener('pointerdown', (e) => { pressedOnBackdrop = e.target.classList?.contains('modal-backdrop'); }, true);
    document.addEventListener('click', (e) => {
        if (e.target.classList?.contains('modal-backdrop') && !pressedOnBackdrop) e.stopPropagation();
    }, true);
})();

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimeLong(ms) {
    const totalMin = Math.floor(ms / 60000);
    if (totalMin < 60) return totalMin + 'min';
    const h = Math.floor(totalMin / 60);
    const m = totalMin % 60;
    if (h < 24) return h + 'h ' + (m > 0 ? m + 'm' : '');
    const d = Math.floor(h / 24);
    return d + 'd ' + (h % 24) + 'h';
}

function formatTime(ms) {
    if (ms <= 0) return '00:00';
    const totalSec = Math.floor(ms / 1000);
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    if (h > 0) return h + ':' + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    return String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
}

// Tick — update countdown text + desktop notifications

function copyInvite(code) {
    navigator.clipboard.writeText(code);
    showToast('Invite code copied!');
}

function goHome() {
    if (currentUser) showTeamList();
    else showLogin();
}

function showToast(message) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

// Collapsible card sections (used by several tabs)
function toggleSection(id, el) {
    document.getElementById(id).classList.toggle('open');
    el.querySelector('.toggle-arrow').classList.toggle('open');
}

// Close any open <details class="menu"> dropdown when clicking elsewhere or pressing Escape.
document.addEventListener('click', (e) => {
    document.querySelectorAll('details.menu[open]').forEach(m => { if (!m.contains(e.target)) m.open = false; });
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') document.querySelectorAll('details.menu[open]').forEach(m => { m.open = false; });
});
