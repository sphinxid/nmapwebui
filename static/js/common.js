/* Shared frontend helpers for NmapWebUI.
 * Loaded synchronously in <head> so page scripts can use these at parse time.
 */

// ---------------------------------------------------------------------------
// Escaping & API
// ---------------------------------------------------------------------------

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * fetch() wrapper: same-origin cookies, JSON in/out, 401 -> login redirect.
 * Resolves to { ok, status, data } where data is parsed JSON or null.
 */
async function api(url, options = {}) {
    const opts = { credentials: 'same-origin', headers: {}, ...options };
    if (opts.body !== undefined && typeof opts.body !== 'string' && !(opts.body instanceof FormData)) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(opts.body);
    }
    let res;
    try {
        res = await fetch(url, opts);
    } catch (e) {
        return { ok: false, status: 0, data: { detail: 'Network error. Is the server reachable?' } };
    }
    if (res.status === 401 && !url.startsWith('/api/auth/')) {
        window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname + window.location.search);
        return { ok: false, status: 401, data: null };
    }
    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
        try { data = await res.json(); } catch (e) { data = null; }
    }
    return { ok: res.ok, status: res.status, data };
}

function errorDetail(result, fallback) {
    return (result && result.data && result.data.detail) || fallback || 'Something went wrong';
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------

function toast(message, type = 'info', timeout = 4000) {
    let host = document.getElementById('toastHost');
    if (!host) {
        host = document.createElement('div');
        host.id = 'toastHost';
        host.className = 'fixed bottom-4 right-4 z-[60] flex flex-col gap-2 items-end';
        host.setAttribute('aria-live', 'polite');
        document.body.appendChild(host);
    }
    const icons = { success: 'fa-check-circle text-emerald-400', error: 'fa-exclamation-circle text-red-400', info: 'fa-info-circle text-blue-400' };
    const el = document.createElement('div');
    el.className = `toast is-${type}`;
    el.setAttribute('role', 'status');
    el.innerHTML = `<i class="fas ${icons[type] || icons.info} mt-0.5"></i>
        <div class="flex-1 break-words">${escapeHtml(message)}</div>
        <button class="text-gray-500 hover:text-white -mr-1" aria-label="Dismiss"><i class="fas fa-times"></i></button>`;
    const remove = () => { el.classList.add('is-leaving'); setTimeout(() => el.remove(), 200); };
    el.querySelector('button').addEventListener('click', remove);
    host.appendChild(el);
    if (timeout > 0) setTimeout(remove, timeout);
    return el;
}
toast.success = (m, t) => toast(m, 'success', t);
toast.error = (m, t) => toast(m, 'error', t === undefined ? 6000 : t);
toast.info = (m, t) => toast(m, 'info', t);

// ---------------------------------------------------------------------------
// Modals & confirm dialog
// ---------------------------------------------------------------------------

const _modalStack = [];

function openModal(id) {
    const modal = typeof id === 'string' ? document.getElementById(id) : id;
    if (!modal) return;
    modal.classList.remove('hidden');
    modal.setAttribute('aria-hidden', 'false');
    _modalStack.push(modal);
    document.body.classList.add('overflow-hidden');
    const focusable = modal.querySelector('input:not([type=hidden]), select, textarea, button:not([data-modal-close])');
    if (focusable) setTimeout(() => focusable.focus(), 10);
}

function closeModal(id) {
    const modal = typeof id === 'string' ? document.getElementById(id) : id;
    if (!modal) return;
    modal.classList.add('hidden');
    modal.setAttribute('aria-hidden', 'true');
    const i = _modalStack.indexOf(modal);
    if (i >= 0) _modalStack.splice(i, 1);
    if (_modalStack.length === 0) document.body.classList.remove('overflow-hidden');
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _modalStack.length) {
        const top = _modalStack[_modalStack.length - 1];
        if (top.dataset.static === undefined) closeModal(top);
    }
});

document.addEventListener('click', (e) => {
    // Backdrop click closes; explicit close buttons use data-modal-close.
    const closeBtn = e.target.closest('[data-modal-close]');
    if (closeBtn) { closeModal(closeBtn.closest('.modal')); return; }
    if (e.target.classList && e.target.classList.contains('modal') && e.target.dataset.static === undefined) {
        closeModal(e.target);
    }
});

/**
 * Promise-based confirm. Resolves true when confirmed.
 * confirmDialog({ title, message, confirmText, danger })
 */
function confirmDialog({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
    return new Promise((resolve) => {
        let modal = document.getElementById('confirmModal');
        if (modal) modal.remove();
        modal = document.createElement('div');
        modal.id = 'confirmModal';
        modal.className = 'modal hidden';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'confirmTitle');
        modal.innerHTML = `
            <div class="modal-panel max-w-md">
                <div class="modal-body">
                    <div class="flex items-start gap-4">
                        <div class="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 ${danger ? 'bg-red-500/10 text-red-400' : 'bg-primary-500/10 text-primary-400'}">
                            <i class="fas ${danger ? 'fa-exclamation-triangle' : 'fa-question'}"></i>
                        </div>
                        <div class="min-w-0">
                            <h2 id="confirmTitle" class="text-lg font-semibold text-white">${escapeHtml(title)}</h2>
                            ${message ? `<p class="text-sm text-gray-400 mt-1">${escapeHtml(message)}</p>` : ''}
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-secondary" data-action="cancel">${escapeHtml(cancelText)}</button>
                    <button type="button" class="${danger ? 'btn-danger' : 'btn-primary'}" data-action="ok">${escapeHtml(confirmText)}</button>
                </div>
            </div>`;
        document.body.appendChild(modal);
        const finish = (val) => { closeModal(modal); modal.remove(); resolve(val); };
        modal.querySelector('[data-action="ok"]').addEventListener('click', () => finish(true));
        modal.querySelector('[data-action="cancel"]').addEventListener('click', () => finish(false));
        modal.addEventListener('click', (e) => { if (e.target === modal) finish(false); });
        const onKey = (e) => { if (e.key === 'Escape') { document.removeEventListener('keydown', onKey, true); finish(false); } };
        document.addEventListener('keydown', onKey, true);
        openModal(modal);
        modal.querySelector('[data-action="ok"]').focus();
    });
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

const STATUS_META = {
    queued:    { cls: 'badge-gray',  icon: 'fa-clock',           label: 'Queued' },
    running:   { cls: 'badge-amber', icon: 'fa-spinner fa-spin', label: 'Running' },
    completed: { cls: 'badge-green', icon: 'fa-check',           label: 'Completed' },
    failed:    { cls: 'badge-red',   icon: 'fa-times',           label: 'Failed' },
    cancelled: { cls: 'badge-gray',  icon: 'fa-ban',             label: 'Cancelled' },
};

function statusBadge(status) {
    const m = STATUS_META[status] || { cls: 'badge-gray', icon: 'fa-question', label: status || 'Unknown' };
    return `<span class="${m.cls}"><i class="fas ${m.icon} text-[10px]"></i>${escapeHtml(m.label)}</span>`;
}

function progressBar(pct, status) {
    pct = Math.max(0, Math.min(100, Number(pct) || 0));
    if (status === 'completed') pct = 100;
    const mod = status === 'failed' ? ' is-failed' : status === 'cancelled' ? ' is-cancelled' : '';
    return `<div class="flex items-center gap-2 min-w-[8rem]">
        <div class="progress flex-1" role="progressbar" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"><div class="progress-fill${mod}" style="width:${pct}%"></div></div>
        <span class="text-xs text-gray-400 w-9 text-right tabular-nums">${pct}%</span>
    </div>`;
}

function formatDateTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    if (isNaN(d)) return '-';
    return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function relativeTime(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    if (isNaN(d)) return '-';
    const diff = Date.now() - d.getTime();
    const abs = Math.abs(diff);
    const future = diff < 0;
    const units = [
        [60000, 'just now', null],
        [3600000, 60000, 'min'],
        [86400000, 3600000, 'hr'],
        [604800000, 86400000, 'day'],
        [2592000000, 604800000, 'wk'],
        [31536000000, 2592000000, 'mo'],
        [Infinity, 31536000000, 'yr'],
    ];
    for (const [limit, div, unit] of units) {
        if (abs < limit) {
            if (unit === null) return future ? 'in <1 min' : 'just now';
            const n = Math.floor(abs / div);
            const label = `${n} ${unit}${n !== 1 && unit !== 'min' ? 's' : ''}`;
            return future ? `in ${label}` : `${label} ago`;
        }
    }
}

/** Relative time with the absolute time on hover; auto-refreshes. */
function timeCell(ts, extraClass = '') {
    if (!ts) return '<span class="text-gray-600">-</span>';
    return `<time datetime="${escapeHtml(ts)}" title="${escapeHtml(formatDateTime(ts))}" data-rel class="text-gray-400 whitespace-nowrap ${extraClass}">${relativeTime(ts)}</time>`;
}

setInterval(() => {
    document.querySelectorAll('time[data-rel]').forEach(el => { el.textContent = relativeTime(el.getAttribute('datetime')); });
}, 30000);

function duration(start, end) {
    if (!start) return '-';
    const s = new Date(start).getTime();
    const e = end ? new Date(end).getTime() : Date.now();
    const diff = Math.max(0, e - s);
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ${sec % 60}s`;
    const hr = Math.floor(min / 60);
    return `${hr}h ${min % 60}m`;
}

function pluralize(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}`; }

// ---------------------------------------------------------------------------
// URL state
// ---------------------------------------------------------------------------

function getParam(name, fallback = '') {
    const v = new URLSearchParams(window.location.search).get(name);
    return v === null ? fallback : v;
}

/** Merge values into the query string without reloading. Empty values are removed. */
function setParams(values) {
    const params = new URLSearchParams(window.location.search);
    Object.entries(values).forEach(([k, v]) => {
        if (v === '' || v === null || v === undefined || v === false) params.delete(k);
        else params.set(k, String(v));
    });
    const qs = params.toString();
    history.replaceState(null, '', window.location.pathname + (qs ? '?' + qs : ''));
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

const PER_PAGE_OPTIONS = [20, 50, 100, 500];

/**
 * Paginator keeps page/per_page in the URL and renders controls.
 *   const pager = new Paginator({ perPageHost, controlsHost, onChange });
 *   pager.query()            -> "page=1&per_page=20"
 *   pager.update(apiResponse)
 */
class Paginator {
    constructor({ perPageHost, controlsHost, onChange, syncUrl = true, defaultPerPage = 20 }) {
        this.perPageHost = typeof perPageHost === 'string' ? document.getElementById(perPageHost) : perPageHost;
        this.controlsHost = typeof controlsHost === 'string' ? document.getElementById(controlsHost) : controlsHost;
        this.onChange = onChange;
        this.syncUrl = syncUrl;
        this.page = syncUrl ? Math.max(1, parseInt(getParam('page', '1')) || 1) : 1;
        const pp = syncUrl ? parseInt(getParam('per_page', String(defaultPerPage))) : defaultPerPage;
        this.perPage = PER_PAGE_OPTIONS.includes(pp) ? pp : defaultPerPage;
        this.pages = 1;
        this.renderPerPage();
    }
    query() { return `page=${this.page}&per_page=${this.perPage}`; }
    setPage(p) {
        if (p < 1 || p > this.pages || p === this.page) return;
        this.page = p; this.persist(); this.onChange();
    }
    setPerPage(n) {
        if (n === this.perPage) return;
        this.perPage = n; this.page = 1; this.persist(); this.renderPerPage(); this.onChange();
    }
    reset() { this.page = 1; this.persist(); }
    persist() { if (this.syncUrl) setParams({ page: this.page === 1 ? '' : this.page, per_page: this.perPage === 20 ? '' : this.perPage }); }
    renderPerPage() {
        if (!this.perPageHost) return;
        this.perPageHost.innerHTML = `<span class="text-xs text-gray-500 mr-2 hidden sm:inline">Per page</span>
            <div class="segment" role="group" aria-label="Items per page">
            ${PER_PAGE_OPTIONS.map(n => `<button type="button" class="${n === this.perPage ? 'active' : ''}" data-pp="${n}">${n}</button>`).join('')}
            </div>`;
        this.perPageHost.querySelectorAll('[data-pp]').forEach(b => b.addEventListener('click', () => this.setPerPage(parseInt(b.dataset.pp))));
    }
    update(data) {
        this.pages = Math.max(1, data.pages || 1);
        if (this.page > this.pages) { this.page = this.pages; this.persist(); }
        if (!this.controlsHost) return;
        if (!data.total || data.total <= data.per_page) { this.controlsHost.classList.add('hidden'); return; }
        this.controlsHost.classList.remove('hidden');
        const start = (data.page - 1) * data.per_page + 1;
        const end = Math.min(data.page * data.per_page, data.total);
        this.controlsHost.innerHTML = `
            <span class="text-sm text-gray-400">Showing <span class="text-gray-200">${start}–${end}</span> of <span class="text-gray-200">${data.total}</span></span>
            <div class="flex items-center gap-2">
                <button type="button" class="btn-secondary btn-sm" data-page="${data.page - 1}" ${data.page <= 1 ? 'disabled' : ''} aria-label="Previous page"><i class="fas fa-chevron-left"></i></button>
                <span class="text-sm text-gray-400 tabular-nums">Page ${data.page} of ${this.pages}</span>
                <button type="button" class="btn-secondary btn-sm" data-page="${data.page + 1}" ${data.page >= this.pages ? 'disabled' : ''} aria-label="Next page"><i class="fas fa-chevron-right"></i></button>
            </div>`;
        this.controlsHost.querySelectorAll('[data-page]').forEach(b => b.addEventListener('click', () => this.setPage(parseInt(b.dataset.page))));
    }
}

function loadingRow(cols, text = 'Loading…') {
    return `<tr><td colspan="${cols}" class="empty"><i class="fas fa-circle-notch fa-spin"></i>${escapeHtml(text)}</td></tr>`;
}
function emptyRow(cols, icon, text, html = '') {
    return `<tr><td colspan="${cols}" class="empty"><i class="fas ${icon}"></i><p>${escapeHtml(text)}</p>${html}</td></tr>`;
}

// ---------------------------------------------------------------------------
// Shell: sidebar, health, logout
// ---------------------------------------------------------------------------

function toggleSidebar(force) {
    const sb = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (!sb) return;
    const open = force !== undefined ? force : sb.classList.contains('-translate-x-full');
    sb.classList.toggle('-translate-x-full', !open);
    overlay && overlay.classList.toggle('hidden', !open);
    const btn = document.getElementById('sidebarToggle');
    btn && btn.setAttribute('aria-expanded', String(open));
}

async function refreshHealth(attempt = 0) {
    const el = document.getElementById('healthIndicator');
    if (!el) return;
    const dot = el.querySelector('[data-dot]');
    const label = el.querySelector('[data-label]');
    const r = await api('/api/health');
    // A single transient fetch failure (e.g. a dropped keep-alive socket)
    // shouldn't flash "unreachable"; retry once before reporting it.
    if (r.status === 0 && attempt === 0) { setTimeout(() => refreshHealth(1), 2000); return; }
    let color = 'bg-red-500', text = 'API unreachable', title = '';
    if (r.ok && r.data) {
        if (r.data.redis !== 'ok') { color = 'bg-red-500'; text = 'Redis down'; title = 'The job queue is unreachable. Scans cannot be started.'; }
        else if (!r.data.workers) { color = 'bg-amber-500'; text = 'No worker'; title = 'No worker process has reported in. Queued scans will not run.'; }
        else { color = 'bg-emerald-500'; text = 'All systems online'; title = `${pluralize(r.data.workers, 'worker')} online · ${r.data.queue_depth} queued`; }
    }
    dot.className = `w-2 h-2 rounded-full ${color} ${color === 'bg-emerald-500' ? 'animate-pulse' : ''}`;
    dot.setAttribute('data-dot', '');
    label.textContent = text;
    el.title = title;
}

async function logout() {
    await api('/api/auth/logout', { method: 'POST' });
    window.location.href = '/login';
}

document.addEventListener('DOMContentLoaded', () => {
    refreshHealth();
    setInterval(refreshHealth, 30000);
    const toggle = document.getElementById('sidebarToggle');
    toggle && toggle.addEventListener('click', () => toggleSidebar());
    const overlay = document.getElementById('sidebarOverlay');
    overlay && overlay.addEventListener('click', () => toggleSidebar(false));
    // Close the drawer when resizing up to desktop so it never sticks open.
    window.addEventListener('resize', () => { if (window.innerWidth >= 1024) toggleSidebar(false); });
});
