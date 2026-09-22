// Timers module: boss timer cards, add/edit modal, kill logging, import/export, templates, history.
// ES module. Talks to the classic shell through globals it can see by name
// (teamBosses, teamData, teamTab, currentTeamId, api, showToast, guard, loadTeamBosses, renderTeamView).
// Exposed to the shell as window.Timers.

import { cardHtml, updateCard, bossState, sortBosses, esc, DAY, fmtDuration } from './timer-cards.js?v=20260922c';

let search = '';
let tickTimer = null;
let refreshTimer = null;

const root = () => document.getElementById('timersContent');
const modalHost = () => document.getElementById('deathModal');
const isPremium = () => !!teamData?.team?.premium_team;
const canManage = () => { const r = teamData?.team?.my_role; return r === 'leader' || r === 'officer'; };
const byId = (id) => teamBosses.find(b => b.id === id);

// ---------------------------------------------------------------- open / loops

export async function open() {
    teamTab = 'timers';
    renderTeamView();
    await loadTeamBosses(currentTeamId);
    if (teamTab !== 'timers') return;
    render();
    startLoops();
}

function startLoops() {
    stopLoops();
    tickTimer = setInterval(() => {
        if (teamTab !== 'timers' || !root()) return stopLoops();
        const now = Date.now();
        for (const b of teamBosses) {
            const el = root().querySelector(`[data-boss-id="${b.id}"]`);
            if (el) updateCard(el, b, now);
        }
        const s = root().querySelector('[data-role="summary"]');
        if (s) s.innerHTML = summaryHtml(now);
    }, 1000);
    refreshTimer = setInterval(async () => {
        if (teamTab !== 'timers' || !root()) return stopLoops();
        await loadTeamBosses(currentTeamId);
        if (teamTab === 'timers') renderList();
    }, 15000);
}

function stopLoops() {
    if (tickTimer) clearInterval(tickTimer);
    if (refreshTimer) clearInterval(refreshTimer);
    tickTimer = refreshTimer = null;
}

async function reload(full = false) {
    await loadTeamBosses(currentTeamId);
    if (teamTab !== 'timers') return;
    full ? render() : renderList();
}

// ---------------------------------------------------------------- render

function filtered() {
    const q = search.trim().toLowerCase();
    return q ? teamBosses.filter(b => b.name.toLowerCase().includes(q) || (b.location || '').toLowerCase().includes(q)) : teamBosses;
}

function summaryHtml(now = Date.now()) {
    if (teamBosses.length === 0) return '';
    const states = teamBosses.map(b => bossState(b, now));
    const up = states.filter(s => s.key === 'spawned' || s.key === 'window').length;
    const next = sortBosses(teamBosses.filter((b, i) => states[i].key === 'waiting' || states[i].key === 'soon'), now)[0];
    const parts = [`${teamBosses.length} timer${teamBosses.length !== 1 ? 's' : ''}`];
    if (up) parts.push(`<span class="t-up">${up} up now</span>`);
    if (next) parts.push(`next: <b>${esc(next.name)}</b> in ${fmtDuration(Math.max(60000, next.next_spawn - now))}`);
    return parts.join(' · ');
}

function listHtml() {
    const list = sortBosses(filtered());
    if (teamBosses.length === 0) {
        return `<div class="t-empty card">
            <div class="t-empty-title">No boss timers yet</div>
            <div class="t-empty-sub">Add the bosses your guild hunts. Everyone in the team sees the same countdowns, and Discord gets pinged before each spawn.</div>
            <button class="btn btn-primary" data-action="add">+ Add your first boss</button>
        </div>`;
    }
    if (list.length === 0) return '<div class="t-empty card"><div class="t-empty-title">No bosses match “' + esc(search) + '”</div></div>';
    const opts = { canManage: canManage() };
    const now = Date.now();
    return list.map(b => cardHtml(b, opts, now)).join('');
}

function render() {
    const el = root();
    if (!el) return;
    const more = [
        `<button class="menu-item" data-action="export">Export JSON</button>`,
        canManage() ? `<button class="menu-item" data-action="import">Import JSON</button>` : '',
        isPremium() ? `<button class="menu-item" data-action="templates">Boss templates</button>` : '',
        isPremium() ? `<button class="menu-item" data-action="history">Kill history</button>` : '',
        canManage() ? `<button class="menu-item menu-item-danger" data-action="removeall">Remove all timers</button>` : '',
    ].filter(Boolean).join('');
    el.innerHTML = `
        <div class="timers-toolbar">
            <input type="search" class="timers-search" data-role="search" placeholder="Search bosses" value="${esc(search)}" autocomplete="off">
            <button class="btn btn-primary" data-action="add">+ Add boss</button>
            <details class="menu" data-role="menu">
                <summary class="btn btn-secondary" title="More">&#8943;</summary>
                <div class="menu-list">${more}</div>
            </details>
            <input type="file" accept=".json" data-role="importfile" hidden>
        </div>
        <div class="timers-summary" data-role="summary">${summaryHtml()}</div>
        <div class="tcards" data-role="list">${listHtml()}</div>`;
    el.onclick = onClick;
    el.oninput = (e) => {
        if (e.target.dataset.role === 'search') { search = e.target.value; renderList(); }
    };
    el.onchange = (e) => {
        if (e.target.dataset.role === 'importfile') importFile(e.target);
    };
}

function renderList() {
    const el = root();
    if (!el) return;
    const list = el.querySelector('[data-role="list"]');
    if (list) list.innerHTML = listHtml();
    const s = el.querySelector('[data-role="summary"]');
    if (s) s.innerHTML = summaryHtml();
}

// ---------------------------------------------------------------- actions

function onClick(e) {
    const btn = e.target.closest('[data-action]');
    if (!btn || !root()?.contains(btn)) return;
    const menu = root().querySelector('[data-role="menu"]');
    if (menu && menu.open && !menu.contains(btn)) menu.open = false;
    const id = btn.dataset.id;
    switch (btn.dataset.action) {
        case 'add': openBossModal(null); break;
        case 'edit': openBossModal(byId(id)); break;
        case 'kill': killBoss(id); break;
        case 'settime': openDeathModal(byId(id)); break;
        case 'delete': deleteBoss(id); break;
        case 'export': exportJson(); break;
        case 'import': root().querySelector('[data-role="importfile"]').click(); break;
        case 'templates': showTemplates(); break;
        case 'history': showHistory(); break;
        case 'removeall': removeAll(); break;
        case 'more': btn.closest('.tcard')?.classList.toggle('open'); break;
    }
    if (menu && btn.closest('.menu-list')) menu.open = false;
}

const killBoss = guard('timers.kill', async (id) => {
    const res = await api('POST', `/api/teams/${currentTeamId}/bosses/${id}/kill`, { deathTime: Date.now() });
    if (res.error) { showToast(res.error); return; }
    await reload();
});

const deleteBoss = guard('timers.delete', async (id) => {
    const b = byId(id);
    if (!confirm(`Remove the timer for ${b?.name || 'this boss'}?`)) return;
    const res = await api('DELETE', `/api/teams/${currentTeamId}/bosses/${id}`);
    if (res.error) { showToast(res.error); return; }
    await reload(true);
});

const removeAll = guard('timers.removeall', async () => {
    if (teamBosses.length === 0) { showToast('No timers to remove'); return; }
    if (!confirm(`Remove ALL ${teamBosses.length} boss timers? This cannot be undone.`)) return;
    for (const b of [...teamBosses]) await api('DELETE', `/api/teams/${currentTeamId}/bosses/${b.id}`);
    await reload(true);
    showToast('All timers removed');
});

// ---------------------------------------------------------------- modals

function closeModal() { modalHost().innerHTML = ''; }

function modal(inner, { wide } = {}) {
    modalHost().innerHTML = `
        <div class="modal-backdrop" data-close="1">
            <div class="card modal-card ${wide ? 'modal-wide' : ''}">${inner}</div>
        </div>`;
    const back = modalHost().firstElementChild;
    back.addEventListener('click', (e) => { if (e.target === back) closeModal(); });
    return back;
}

const TYPE_LABEL = { interval: 'Every X hours', fixed: 'Daily at a time', weekly: 'Weekly', twicedaily: 'Twice daily', biweekly: 'Twice a week' };

function bossFormHtml(b) {
    const j = (v) => { try { return typeof v === 'string' ? JSON.parse(v) : (v || []); } catch { return []; } };
    const twice = b?.type === 'twicedaily' ? j(b.biweekly_days) : [];
    const bi = b?.type === 'biweekly' ? j(b.biweekly_days) : [];
    const ih = b?.interval_ms ? Math.floor(b.interval_ms / 3600000) : '';
    const im = b?.interval_ms ? Math.round((b.interval_ms % 3600000) / 60000) : '';
    const daySel = (id, val) => `<select id="${id}">${DAY.map((d, i) => `<option value="${i}" ${val === i ? 'selected' : ''}>${d}</option>`).join('')}</select>`;
    return `
        <h2>${b ? 'Edit boss' : 'Add boss'}</h2>
        <form class="tform" id="bossForm">
            <label class="tf-field tf-wide"><span>Boss name</span><input id="bfName" maxlength="100" required value="${esc(b?.name || '')}" placeholder="e.g. Kundun"></label>
            <label class="tf-field tf-wide"><span>Location / channel <em>optional</em></span><input id="bfLocation" maxlength="80" value="${esc(b?.location || '')}" placeholder="e.g. Kalima 7, Channel 3"></label>
            <label class="tf-field"><span>Spawn rule</span>
                <select id="bfType">${Object.entries(TYPE_LABEL).map(([k, v]) => `<option value="${k}" ${(b?.type || 'interval') === k ? 'selected' : ''}>${v}</option>`).join('')}</select>
            </label>
            <div class="tf-field tf-rule" data-rule="interval"><span>Respawn after</span>
                <div class="tf-inline"><input id="bfHours" type="number" min="0" max="999" placeholder="h" value="${ih}"><b>h</b><input id="bfMinutes" type="number" min="0" max="59" placeholder="m" value="${im}"><b>m</b></div>
            </div>
            <label class="tf-field tf-rule" data-rule="fixed"><span>Time</span><input id="bfFixedTime" type="time" value="${esc(b?.fixed_time || '')}"></label>
            <div class="tf-field tf-rule" data-rule="weekly"><span>Day &amp; time</span>
                <div class="tf-inline">${daySel('bfWeeklyDay', b?.weekly_day ?? 1)}<input id="bfWeeklyTime" type="time" value="${esc(b?.weekly_time || '')}"></div>
            </div>
            <div class="tf-field tf-rule" data-rule="twicedaily"><span>Times</span>
                <div class="tf-inline"><input id="bfTwice1" type="time" value="${esc(twice[0] || '')}"><input id="bfTwice2" type="time" value="${esc(twice[1] || '')}"></div>
            </div>
            <div class="tf-field tf-rule tf-wide" data-rule="biweekly"><span>Two days &amp; times</span>
                <div class="tf-inline">${daySel('bfBiDay1', bi[0]?.day ?? 1)}<input id="bfBiTime1" type="time" value="${esc(bi[0]?.time || '')}"><span class="tf-amp">&amp;</span>${daySel('bfBiDay2', bi[1]?.day ?? 4)}<input id="bfBiTime2" type="time" value="${esc(bi[1]?.time || '')}"></div>
            </div>
            <label class="tf-field"><span>Spawn window <em>optional, minutes</em></span><input id="bfWindow" type="number" min="0" max="1440" placeholder="0" value="${b?.window_ms ? Math.round(b.window_ms / 60000) : ''}"></label>
            <label class="tf-field"><span>Alert before <em>minutes</em></span><input id="bfAlert" type="number" min="1" max="120" value="${b?.alert_minutes ?? 5}"></label>
            <label class="tf-field"><span>Auto-reset if not killed <em>minutes</em></span><input id="bfReset" type="number" min="1" max="1440" value="${b?.auto_reset_minutes ?? 5}"></label>
            <p class="tf-help tf-wide">A spawn window means the boss can appear any time between the countdown ending and the window closing. With a window, the timer resets when the window closes instead of after the auto-reset minutes.</p>
            <div class="tf-actions tf-wide">
                <button type="button" class="btn btn-secondary" data-close="1">Cancel</button>
                <button type="submit" class="btn btn-primary">${b ? 'Save changes' : 'Add boss'}</button>
            </div>
        </form>`;
}

function openBossModal(b) {
    const back = modal(bossFormHtml(b));
    const form = back.querySelector('#bossForm');
    const showRule = () => {
        const t = form.querySelector('#bfType').value;
        form.querySelectorAll('.tf-rule').forEach(el => { el.style.display = el.dataset.rule === t ? '' : 'none'; });
    };
    showRule();
    form.querySelector('#bfType').addEventListener('change', showRule);
    back.querySelector('[data-close]:not(.modal-backdrop)').addEventListener('click', closeModal);
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = readBossForm(form);
        if (!body) return;
        const res = b
            ? await api('PUT', `/api/teams/${currentTeamId}/bosses/${b.id}`, body)
            : await api('POST', `/api/teams/${currentTeamId}/bosses`, body);
        if (res.error) { showToast(res.error); return; }
        closeModal();
        showToast(b ? 'Boss updated' : `${body.name} added`);
        await reload(true);
    });
    setTimeout(() => form.querySelector('#bfName').focus(), 0);
}

function readBossForm(form) {
    const v = (id) => form.querySelector('#' + id).value;
    const name = v('bfName').trim();
    if (!name) { showToast('Boss name required'); return null; }
    const type = v('bfType');
    const body = {
        name, type,
        location: v('bfLocation').trim() || null,
        alertMinutes: parseInt(v('bfAlert')) || 5,
        autoResetMinutes: parseInt(v('bfReset')) || 5,
        windowMs: (parseInt(v('bfWindow')) || 0) * 60000,
    };
    if (type === 'interval') {
        const h = parseInt(v('bfHours')) || 0, m = parseInt(v('bfMinutes')) || 0;
        if (h === 0 && m === 0) { showToast('Set the respawn time'); return null; }
        body.intervalMs = (h * 3600 + m * 60) * 1000;
    } else if (type === 'fixed') {
        body.fixedTime = v('bfFixedTime'); if (!body.fixedTime) { showToast('Pick a time'); return null; }
    } else if (type === 'weekly') {
        body.weeklyDay = parseInt(v('bfWeeklyDay')); body.weeklyTime = v('bfWeeklyTime');
        if (!body.weeklyTime) { showToast('Pick a time'); return null; }
    } else if (type === 'twicedaily') {
        const t1 = v('bfTwice1'), t2 = v('bfTwice2');
        if (!t1 || !t2) { showToast('Pick both times'); return null; }
        body.twiceDailyTimes = [t1, t2];
    } else if (type === 'biweekly') {
        const t1 = v('bfBiTime1'), t2 = v('bfBiTime2');
        if (!t1 || !t2) { showToast('Pick both times'); return null; }
        body.biweeklyDays = [{ day: parseInt(v('bfBiDay1')), time: t1 }, { day: parseInt(v('bfBiDay2')), time: t2 }];
    }
    return body;
}

function openDeathModal(b) {
    if (!b) return;
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const local = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T${pad(now.getHours())}:${pad(now.getMinutes())}`;
    const back = modal(`
        <h2>Set kill time</h2>
        <p class="tf-help">When was <b>${esc(b.name)}</b> killed? The next spawn is calculated from this.</p>
        <form class="tform" id="deathForm">
            <label class="tf-field tf-wide"><span>Killed at</span><input id="dfWhen" type="datetime-local" value="${local}" max="${local}" required></label>
            <div class="tf-actions tf-wide">
                <button type="button" class="btn btn-secondary" data-close="1">Cancel</button>
                <button type="submit" class="btn btn-primary">Save</button>
            </div>
        </form>`);
    back.querySelector('[data-close]:not(.modal-backdrop)').addEventListener('click', closeModal);
    back.querySelector('#deathForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const t = new Date(back.querySelector('#dfWhen').value).getTime();
        if (isNaN(t)) { showToast('Pick a valid time'); return; }
        const res = await api('POST', `/api/teams/${currentTeamId}/bosses/${b.id}/kill`, { deathTime: t });
        if (res.error) { showToast(res.error); return; }
        closeModal();
        showToast('Kill time saved');
        await reload();
    });
}

// ---------------------------------------------------------------- export / import

function exportJson() {
    if (teamBosses.length === 0) { showToast('No timers to export'); return; }
    const j = (v) => { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return null; } };
    const data = {
        version: 2,
        exportedAt: Date.now(),
        bosses: teamBosses.map(b => ({
            name: b.name, type: b.type, location: b.location || null,
            alert_minutes: b.alert_minutes, auto_reset_minutes: b.auto_reset_minutes || 5, window_ms: b.window_ms || 0,
            last_death: b.last_death || null,
            interval_ms: b.type === 'interval' ? b.interval_ms : undefined,
            fixed_time: b.type === 'fixed' ? b.fixed_time : undefined,
            weekly_day: b.type === 'weekly' ? b.weekly_day : undefined,
            weekly_time: b.type === 'weekly' ? b.weekly_time : undefined,
            twice_daily_times: b.type === 'twicedaily' ? j(b.biweekly_days) : undefined,
            biweekly_days: b.type === 'biweekly' ? j(b.biweekly_days) : undefined,
        })),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `boss-timers-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${teamBosses.length} timer${teamBosses.length !== 1 ? 's' : ''}`);
}

async function importFile(input) {
    const file = input.files[0];
    input.value = '';
    if (!file) return;
    try {
        const data = JSON.parse(await file.text());
        if (!Array.isArray(data.bosses) || data.bosses.length === 0) { showToast('No bosses in that file'); return; }
        const existing = new Set(teamBosses.map(b => b.name.toLowerCase()));
        const fresh = data.bosses.filter(b => b.name && typeof b.name === 'string' && !existing.has(b.name.toLowerCase()));
        const skipped = data.bosses.length - fresh.length;
        if (!confirm(`Import ${fresh.length} boss${fresh.length !== 1 ? 'es' : ''}?${skipped ? `\n${skipped} already exist and will be skipped.` : ''}`)) return;
        const valid = new Set(['interval', 'fixed', 'weekly', 'twicedaily', 'biweekly']);
        let added = 0;
        for (const b of fresh) {
            if (!valid.has(b.type) || b.name.length > 100) continue;
            const body = {
                name: b.name, type: b.type, location: b.location || null,
                alertMinutes: b.alert_minutes || 5, autoResetMinutes: b.auto_reset_minutes || 5, windowMs: b.window_ms || 0,
                intervalMs: b.interval_ms, fixedTime: b.fixed_time, weeklyDay: b.weekly_day, weeklyTime: b.weekly_time,
                twiceDailyTimes: b.twice_daily_times, biweeklyDays: b.biweekly_days,
            };
            const res = await api('POST', `/api/teams/${currentTeamId}/bosses`, body);
            if (res?.id && b.last_death) await api('POST', `/api/teams/${currentTeamId}/bosses/${res.id}/kill`, { deathTime: b.last_death });
            if (res?.id) added++;
        }
        await reload(true);
        showToast(`Imported ${added} boss${added !== 1 ? 'es' : ''}${skipped ? `, skipped ${skipped}` : ''}`);
    } catch (e) {
        showToast('Could not import: ' + e.message);
    }
}

// ---------------------------------------------------------------- premium: templates + history

async function showTemplates() {
    const data = await api('GET', '/api/boss-templates');
    const templates = data.templates || [];
    const rows = templates.length === 0 ? '<div class="t-empty-sub">No templates yet.</div>' : templates.map(t => {
        let n = 0; try { n = JSON.parse(t.bosses).length; } catch {}
        return `<div class="t-row"><div><b>${esc(t.name)}</b> <span class="t-dim">${esc(t.game)} · ${n} bosses</span></div>
            <button class="btn btn-sm btn-primary" data-tpl="${t.id}">Import</button></div>`;
    }).join('');
    const back = modal(`<h2>Boss templates</h2>${rows}
        <div class="tf-actions"><button class="btn btn-secondary btn-sm" data-act="save">Save current timers as template</button><button class="btn btn-secondary btn-sm" data-close="1">Close</button></div>`, { wide: true });
    back.addEventListener('click', async (e) => {
        const tpl = e.target.closest('[data-tpl]');
        if (tpl) {
            const res = await api('POST', `/api/teams/${currentTeamId}/bosses/import-template`, { templateId: tpl.dataset.tpl });
            if (res.error) { showToast(res.error); return; }
            closeModal(); showToast(`Imported ${res.count} bosses`); await reload(true); return;
        }
        if (e.target.closest('[data-act="save"]')) {
            const name = prompt('Template name:'); if (!name) return;
            const game = prompt('Game name:'); if (!game) return;
            const j = (v) => { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return null; } };
            const bosses = teamBosses.map(b => ({ name: b.name, type: b.type, intervalMs: b.interval_ms, fixedTime: b.fixed_time, weeklyDay: b.weekly_day, weeklyTime: b.weekly_time, biweeklyDays: j(b.biweekly_days), alertMinutes: b.alert_minutes }));
            const res = await api('POST', '/api/boss-templates', { name, game, bosses });
            if (res.error) { showToast(res.error); return; }
            showToast('Template saved'); closeModal(); return;
        }
        if (e.target.closest('[data-close]:not(.modal-backdrop)')) closeModal();
    });
}

async function showHistory() {
    const data = await api('GET', `/api/teams/${currentTeamId}/bosses/history`);
    if (data.error) { showToast(data.error); return; }
    const stats = (data.stats || []).map(s => `<div class="t-row"><span>${esc(s.boss_name)}</span><span class="t-up">${s.kill_count} kill${s.kill_count !== 1 ? 's' : ''}</span></div>`).join('');
    const hist = (data.history || []).slice(0, 30).map(h => `<div class="t-row t-row-sm"><span>${esc(h.boss_name)}</span><span class="t-dim">${esc(h.killed_by_name || 'unknown')} · ${new Date(h.killed_at).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })}</span></div>`).join('');
    const back = modal(`<h2>Kill history</h2>
        ${stats ? `<h3 class="t-h3">Per boss</h3>${stats}` : ''}
        <h3 class="t-h3">Recent kills</h3>${hist || '<div class="t-empty-sub">No kills logged yet.</div>'}
        <div class="tf-actions"><button class="btn btn-secondary btn-sm" data-close="1">Close</button></div>`, { wide: true });
    back.addEventListener('click', (e) => { if (e.target.closest('[data-close]:not(.modal-backdrop)')) closeModal(); });
}

window.Timers = { open, refresh: () => reload() };
