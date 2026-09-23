// Rally attendance view (inside Events): the review queue for officers, each member's own claims,
// and the points summary. Claims arrive from Discord (/here with a screenshot, /rollcall by an officer).
// ES module used by events.js. Uses shell globals by name (currentTeamId, teamData, api, token, API, showToast, guard).

import { esc } from './timer-cards.js?v=20260924b';

let claims = [], pending = 0, officer = false, summary = null, days = 7, filter = 'pending', query = '';
const openDays = new Set();   // days the user opened ('d') or closed ('!d'); default: newest day + days with pending claims open

const isOfficer = () => { const r = teamData?.team?.my_role; return r === 'leader' || r === 'officer'; };
const T = () => currentTeamId;
const imgUrl = (id) => `${API}/api/teams/${T()}/attendance/${id}/download?token=${encodeURIComponent(token)}`;

export async function loadAttendance() {
    const [c, s] = await Promise.all([
        api('GET', `/api/teams/${T()}/attendance?status=all&days=30`),
        api('GET', `/api/teams/${T()}/attendance/summary?days=${days}`),
    ]);
    claims = c.claims || []; pending = c.pending || 0; officer = !!c.officer; summary = s;
    if (!officer) filter = 'all';
}

export function attendanceHtml() {
    const q = query.trim().toLowerCase();
    const shown = claims.filter(c => (filter === 'all' || c.status === filter)
        && (!q || c.username.toLowerCase().includes(q) || c.bosses.some(b => b.name.toLowerCase().includes(q))));
    const flagChip = (f) => `<span class="chip chip-warn" title="${esc(f.text)}">${esc(f.text)}</span>`;
    const statusChip = (c) => c.status === 'pending' ? '<span class="chip chip-muted">Pending</span>' : c.status === 'approved' ? '<span class="chip chip-success">Approved</span>' : '<span class="chip chip-danger">Rejected</span>';

    // Pending claims need a decision: full row with thumbnail, flags spelled out, buttons.
    const fullRow = (c) => {
        const bosses = c.bosses.map(b => b.name).join(' + ');
        const when = new Date(c.created_at * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
        const src = c.source === 'rollcall' ? 'roll call' : 'screenshot';
        const actions = officer ? `<button class="btn btn-sm btn-primary" data-att="approve" data-id="${c.id}">Approve</button><button class="btn btn-sm btn-secondary" data-att="reject" data-id="${c.id}">Reject</button>` : statusChip(c);
        return `<div class="card att-row is-${c.status}">
            ${c.hasImage ? `<img class="att-thumb" src="${imgUrl(c.id)}" alt="" loading="lazy" data-att="zoom" data-id="${c.id}">` : `<div class="att-thumb-none">${src}</div>`}
            <div class="att-body">
                <div class="att-name">${esc(c.username)} <span class="t-dim">· ${esc(bosses)} · ${c.points} pt${c.points === 1 ? '' : 's'}</span></div>
                <div class="att-meta">${when} · ${src}${c.note ? ` · <span class="att-note">${esc(c.note)}</span>` : ''}</div>
                ${c.flags?.length ? `<div class="att-meta" style="white-space:normal;margin-top:3px">${c.flags.map(flagChip).join(' ')}</div>` : ''}
            </div>
            <div class="att-actions">${actions}</div>
        </div>`;
    };
    // Decided claims are history: one dense line, screenshot one click away.
    const lineRow = (c) => {
        const when = new Date(c.created_at * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
        const warn = c.flags?.length ? `<span class="att-warn" title="${esc(c.flags.map(f => f.text).join('\n'))}">&#9888; ${c.flags.length}</span>` : '<span></span>';
        const pic = c.hasImage ? `<button class="att-pic" data-att="zoom" data-id="${c.id}" title="View screenshot">&#128444;</button>` : `<span class="att-pic t-dim" title="Roll call">&#128203;</span>`;
        return `<div class="att-line is-${c.status}">${pic}<span class="att-line-name">${esc(c.username)}</span><span class="att-line-boss">${esc(c.bosses.map(b => b.name).join(' + '))}</span>${warn}<span class="t-dim">${when}</span><span class="att-line-pts">${c.status === 'rejected' ? '&mdash;' : '+' + c.points}</span></div>`;
    };

    const byDay = new Map();
    for (const c of shown) { if (!byDay.has(c.day)) byDay.set(c.day, []); byDay.get(c.day).push(c); }
    const dayKeys = [...byDay.keys()].sort().reverse();
    const groups = dayKeys.map((day, i) => {
        const list = byDay.get(day);
        const p = list.filter(c => c.status === 'pending').length;
        const pts = list.filter(c => c.status === 'approved').reduce((a, c) => a + c.points, 0);
        const people = new Set(list.map(c => c.user_id)).size;
        const open = openDays.has(day) || (!openDays.has('!' + day) && (i === 0 || p > 0 || !!q));
        const pendingRows = list.filter(c => c.status === 'pending').map(fullRow).join('');
        const lines = list.filter(c => c.status !== 'pending').map(lineRow).join('');
        const label = new Date(day + 'T12:00:00').toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
        return `<details class="att-day" data-day="${day}" ${open ? 'open' : ''}>
            <summary><b>${label}</b><span class="t-dim">${people} member${people === 1 ? '' : 's'} · ${list.length} claim${list.length === 1 ? '' : 's'}${pts ? ` · +${pts} pts` : ''}</span>${p ? `<span class="chip chip-warn">${p} pending</span>` : ''}</summary>
            ${pendingRows ? `<div class="att-rows">${pendingRows}</div>` : ''}
            ${lines ? `<div class="att-lines card">${lines}</div>` : ''}
        </details>`;
    }).join('');

    const empty = `<div class="t-empty card"><div class="t-empty-title">${q ? 'Nothing matches' : filter === 'pending' ? 'Nothing to review' : 'No attendance yet'}</div><div class="t-empty-sub">Members check in from Discord with <b>/here</b> and a screenshot; officers can log a whole rally with <b>/rollcall</b>. Approved rallies award points automatically.</div></div>`;
    const sum = summary?.members?.length ? `<section class="card att-summary">
        <div class="home-card-head"><h4>Points, last ${summary.days} days</h4><span class="sub-nav">${[7, 30, 90].map(d => `<button class="${days === d ? 'active' : ''}" data-att="days" data-days="${d}">${d}d</button>`).join('')}</span></div>
        <div class="att-summary-scroll"><table><thead><tr><th>Member</th><th class="num">Rallies</th><th class="num">Points</th></tr></thead><tbody>
        ${summary.members.map(m => `<tr><td>${esc(m.username)}</td><td class="num">${m.rallies}</td><td class="num">${m.points}</td></tr>`).join('')}
        </tbody></table></div></section>` : '';
    return `
        <div class="att-toolbar">
            ${officer ? `<div class="sub-nav">${[['pending', `Pending${pending ? ' · ' + pending : ''}`], ['approved', 'Approved'], ['rejected', 'Rejected'], ['all', 'All']].map(([k, l]) => `<button class="${filter === k ? 'active' : ''}" data-att="filter" data-filter="${k}">${l}</button>`).join('')}</div>` : ''}
            <input type="search" class="timers-search att-search" data-att-search placeholder="Search member or boss" value="${esc(query)}">
            ${officer && pending ? `<button class="btn btn-sm btn-primary" data-att="approve-all">Approve all unflagged</button>` : ''}
        </div>
        <div class="att-days">${groups || empty}</div>
        ${sum}`;
}

// Search box + remembering which days were opened/closed (events.js forwards these).
export function onAttendanceInput(el) {
    if (el.matches && el.matches('[data-att-search]')) { query = el.value; return 'list'; }
    return null;
}
export function onAttendanceToggle(details) {
    const day = details.dataset.day; if (!day) return;
    openDays.delete(day); openDays.delete('!' + day);
    openDays.add(details.open ? day : '!' + day);
}

// Returns true when it handled the click (events.js re-renders after an await).
export async function onAttendanceClick(btn) {
    const act = btn.dataset.att;
    if (!act) return false;
    if (act === 'filter') { filter = btn.dataset.filter; return true; }
    if (act === 'days') { days = Number(btn.dataset.days) || 7; summary = await api('GET', `/api/teams/${T()}/attendance/summary?days=${days}`); return true; }
    if (act === 'zoom') {
        const box = Object.assign(document.createElement('div'), { className: 'att-lightbox' });
        box.innerHTML = `<img src="${imgUrl(btn.dataset.id)}" alt="">`;
        box.addEventListener('click', () => box.remove());
        document.body.appendChild(box);
        return false;
    }
    if (act === 'approve' || act === 'reject') {
        const res = await api('POST', `/api/teams/${T()}/attendance/${btn.dataset.id}/${act}`);
        if (res.error) { showToast(res.error); return false; }
        showToast(act === 'approve' ? 'Approved, points awarded' : 'Rejected');
        await loadAttendance();
        return true;
    }
    if (act === 'approve-all') {
        const res = await api('POST', `/api/teams/${T()}/attendance/approve-all`);
        if (res.error) { showToast(res.error); return false; }
        showToast(`Approved ${res.approved}${res.skippedFlagged ? `, ${res.skippedFlagged} flagged left for review` : ''}`);
        await loadAttendance();
        return true;
    }
    return false;
}
