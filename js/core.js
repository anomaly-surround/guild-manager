// App config (API base), shared session state and the double-tap guard()

const API = 'https://guild-manager.xpropics.workers.dev';
let token = localStorage.getItem('gm_token') || '';
let currentUser = null;
let currentTeamId = null;

// Points system name helper (customizable per team, defaults to "DKP")
let _pointsName = 'DKP';
function ptsName() { return _pointsName || 'DKP'; }

// Double-tap guard
const _busy = {};
function guard(name, fn) {
    return async function(...args) {
        if (_busy[name]) return;
        _busy[name] = true;
        try { await fn(...args); }
        finally { _busy[name] = false; }
    };
}
