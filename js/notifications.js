// Desktop notifications + Do-Not-Disturb toggle

// Desktop notifications
let dndMode = localStorage.getItem('gm_dnd') === 'true';
const notifiedBosses = new Set(); // track which bosses we already notified

function requestNotifPermission() {
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
}

function sendDesktopNotif(title, body, tag) {
    if (dndMode) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (notifiedBosses.has(tag)) return;
    notifiedBosses.add(tag);
    // Auto-clear tag after 10 minutes so it can re-notify next cycle
    setTimeout(() => notifiedBosses.delete(tag), 600000);
    try {
        const n = new Notification(title, { body, icon: 'icon.svg', tag, requireInteraction: true });
        n.onclick = () => { window.focus(); n.close(); };
    } catch(e) {}
}

function toggleDND() {
    dndMode = !dndMode;
    localStorage.setItem('gm_dnd', dndMode);
    updateDNDBadge();
}

function updateDNDBadge() {
    const el = document.getElementById('dndBtn');
    if (el) {
        el.textContent = dndMode ? '🔕 DND On' : '🔔 Alerts On';
        el.style.background = dndMode ? '#7f1d1d' : '#16653466';
        el.style.color = dndMode ? '#fca5a5' : '#4ade80';
    }
}

requestNotifPermission();
