import { fmtDate, timeAgo, escapeHtml } from '/js/utils.js';
import { toast } from '/js/ui.js';

let state = {
  alerts: { iberian: [], european: [] },
  loading: false,
  lastRun: null,
  view: 'group',
  priorityFilter: 'all',
  zoneFilter: 'all',
  daysFilter: 'all',
  sortBy: 'days-desc',
};

const PRIORITY_LEVELS = {
  critical: { threshold: 21, icon: '🔥', label: 'CRITICAL', badgeClass: 'badge-danger', bg: '#fff5f5', border: '#dc2626', textColor: '#dc2626' },
  warning:  { threshold: 14, icon: '⚠️', label: 'WARNING',  badgeClass: 'badge-warning', bg: '#fff8f0', border: '#ea580c', textColor: '#ea580c' },
  normal:   { threshold: 0,  icon: '●',  label: '',       badgeClass: 'badge-info',    bg: '#ffffff', border: 'var(--hairline)', textColor: 'inherit' },
};

function getPriority(days) {
  if (days > 21) return 'critical';
  if (days >= 14) return 'warning';
  return 'normal';
}

async function loadAlerts() {
  state.loading = true;
  renderContent();
  try {
    const res = await fetch('/api/proxy/admin/access-alerts');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.alerts = { iberian: data.iberian || [], european: data.european || [] };
    state.lastRun = data.last_run || null;
  } catch (err) {
    console.error('[AccessAlerts] load error:', err);
    state.alerts = { iberian: [], european: [] };
  }
  state.loading = false;
  renderContent();
  wireEvents();
}

function getFilteredAlerts() {
  let all = [
    ...state.alerts.iberian.map(a => ({ ...a, _zone: 'iberian' })),
    ...state.alerts.european.map(a => ({ ...a, _zone: 'european' })),
  ];
  if (state.priorityFilter !== 'all') {
    all = all.filter(a => getPriority(a.days_since_fulfillment || 0) === state.priorityFilter);
  }
  if (state.zoneFilter !== 'all') {
    all = all.filter(a => a._zone === state.zoneFilter);
  }
  if (state.daysFilter !== 'all') {
    const minDays = parseInt(state.daysFilter, 10);
    all = all.filter(a => (a.days_since_fulfillment || 0) >= minDays);
  }
  switch (state.sortBy) {
    case 'days-desc': all.sort((a, b) => (b.days_since_fulfillment || 0) - (a.days_since_fulfillment || 0)); break;
    case 'days-asc':  all.sort((a, b) => (a.days_since_fulfillment || 0) - (b.days_since_fulfillment || 0)); break;
    case 'order-id':  all.sort((a, b) => (a.order_id || 0) - (b.order_id || 0)); break;
  }
  return all;
}

function getSummary() {
  const all = [
    ...state.alerts.iberian.map(a => ({ ...a, _zone: 'iberian' })),
    ...state.alerts.european.map(a => ({ ...a, _zone: 'european' })),
  ];
  return {
    total: all.length,
    critical: all.filter(a => getPriority(a.days_since_fulfillment || 0) === 'critical').length,
    warning: all.filter(a => getPriority(a.days_since_fulfillment || 0) === 'warning').length,
    normal: all.filter(a => getPriority(a.days_since_fulfillment || 0) === 'normal').length,
    iberian: all.filter(a => a._zone === 'iberian').length,
    european: all.filter(a => a._zone === 'european').length,
  };
}

function cardStyle(days) {
  const p = PRIORITY_LEVELS[getPriority(days)];
  return `background:${p.bg}; border-left:4px solid ${p.border};`;
}
function rowStyle(days) {
  const p = PRIORITY_LEVELS[getPriority(days)];
  return `background:${p.bg};`;
}
function daysHtml(days) {
  const p = PRIORITY_LEVELS[getPriority(days)];
  const bold = getPriority(days) === 'critical' ? 'font-weight:700;' : getPriority(days) === 'warning' ? 'font-weight:600;' : '';
  return `<span style="color:${p.textColor}; ${bold}">${days}d</span>`;
}
function priorityLabel(days) {
  const p = PRIORITY_LEVELS[getPriority(days)];
  if (!p.label) return '';
  return `<span class="badge ${p.badgeClass}" style="margin-left:var(--space-1);">${p.icon} ${p.label}</span>`;
}

function alertCard(a) {
  const days = a.days_since_fulfillment || 0;
  const zoneLabel = a._zone === 'iberian' ? 'Iberian' : 'European';
  const zoneBadge = a._zone === 'iberian' ? 'badge-info' : 'badge-warning';
  return `
    <div class="card alert-card" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}" style="${cardStyle(days)} cursor:pointer;">
      <div class="card-header">
        <div class="card-title">Order ${escapeHtml(String(a.order_id))} ${priorityLabel(days)}</div>
        <div class="col-mono card-meta">${escapeHtml(String(a.piece_id))}</div>
      </div>
      <p class="card-meta">${daysHtml(days)} · Customer ID: ${escapeHtml(String(a.customer_id))} · Fulfilled ${fmtDate(a.fulfillment_date)}</p>
      <p style="margin-top: var(--space-2);"><span class="badge ${zoneBadge}">${zoneLabel}</span></p>
      <div style="display:flex; gap: var(--space-2); margin-top: var(--space-3); flex-wrap: wrap;">
        <button type="button" class="btn btn-sm btn-secondary" data-action="contact-client" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}">Contact client</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="mark-verbal" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}">Mark verbal</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="send-magic-link" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}">Send magic link</button>
        <button type="button" class="btn btn-sm btn-danger" data-action="mark-issue" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}">Mark issue detected</button>
      </div>
    </div>
  `;
}

function alertRow(a) {
  const days = a.days_since_fulfillment || 0;
  const zoneLabel = a._zone === 'iberian' ? 'IB' : 'EU';
  const zoneBadge = a._zone === 'iberian' ? 'badge-info' : 'badge-warning';
  return `
    <tr class="alert-row" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}" style="${rowStyle(days)} cursor:pointer;">
      <td>${daysHtml(days)} ${priorityLabel(days)}</td>
      <td><span class="badge ${zoneBadge}">${zoneLabel}</span></td>
      <td>${escapeHtml(String(a.order_id))}</td>
      <td>${escapeHtml(String(a.piece_id))}</td>
      <td>${escapeHtml(String(a.customer_id))}</td>
      <td>${fmtDate(a.fulfillment_date)}</td>
      <td style="white-space: nowrap; text-align:right;">
        <button type="button" class="btn btn-xs btn-secondary" data-action="contact-client" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}" title="Contact">📧</button>
        <button type="button" class="btn btn-xs btn-secondary" data-action="mark-verbal" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" title="Verbal">✓</button>
        <button type="button" class="btn btn-xs btn-secondary" data-action="send-magic-link" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" data-customer-id="${escapeHtml(String(a.customer_id))}" title="Magic link">🔗</button>
        <button type="button" class="btn btn-xs btn-danger" data-action="mark-issue" data-order-id="${escapeHtml(String(a.order_id))}" data-piece-id="${escapeHtml(String(a.piece_id))}" title="Issue">⚠️</button>
      </td>
    </tr>
  `;
}

function renderGroupView(list) {
  const groups = { critical: [], warning: [], normal: [] };
  list.forEach(a => groups[getPriority(a.days_since_fulfillment || 0)].push(a));
  const order = ['critical', 'warning', 'normal'];
  const titles = { critical: '🔥 CRITICAL', warning: '⚠️ WARNING', normal: '● NORMAL' };
  const sections = [];
  order.forEach(key => {
    const items = groups[key];
    if (items.length === 0) return;
    const p = PRIORITY_LEVELS[key];
    const isGrid = state.view === 'grid';
    sections.push(`
      <div style="margin-bottom: var(--space-5);">
        <div style="display:flex; align-items:center; gap: var(--space-2); margin-bottom: var(--space-3); padding-bottom: var(--space-2); border-bottom: 2px solid ${p.border};">
          <span style="font-size: var(--size-lg); font-weight: 600; color: ${p.textColor};">${titles[key]}</span>
          <span class="card-meta">— ${items.length} alert${items.length > 1 ? 's' : ''}</span>
        </div>
        ${isGrid ? `<div class="card-grid">${items.map(alertCard).join('')}</div>` : `<table class="data-table"><thead><tr><th>Days</th><th>Zone</th><th>Order</th><th>Piece</th><th>Customer</th><th>Fulfilled</th><th style="text-align:right;">Actions</th></tr></thead><tbody>${items.map(alertRow).join('')}</tbody></table>`}
      </div>
    `);
  });
  return sections.join('');
}

function renderContent() {
  const root = document.getElementById('tab-root');
  if (!root) return;
  const list = getFilteredAlerts();
  const summary = getSummary();
  const lastRunText = state.lastRun ? `Last run: ${timeAgo(state.lastRun)}` : '';
  const isGroup = state.view === 'group';

  const priorityPills = [
    { key: 'all', label: `All (${summary.total})` },
    { key: 'critical', label: `🔥 Critical (${summary.critical})` },
    { key: 'warning', label: `⚠️ Warning (${summary.warning})` },
    { key: 'normal', label: `● Normal (${summary.normal})` },
  ];
  const zonePills = [
    { key: 'all', label: `All zones` },
    { key: 'iberian', label: `Iberian (${summary.iberian})` },
    { key: 'european', label: `European (${summary.european})` },
  ];
  const daysPills = [
    { key: 'all', label: 'All days' },
    { key: '7', label: '7+' },
    { key: '14', label: '14+' },
    { key: '21', label: '21+' },
    { key: '30', label: '30+' },
  ];
  const sortOptions = [
    { key: 'days-desc', label: 'Oldest first' },
    { key: 'days-asc', label: 'Newest first' },
    { key: 'order-id', label: 'Order ID' },
  ];

  root.innerHTML = `
    <header class="tab-header">
      <h1>Access alerts</h1>
      <p class="tab-subtitle">Pieces that arrived, but no one opened the room yet. <span class="card-meta">${lastRunText}</span></p>
    </header>
    <div class="tab-content">
      <div style="display: flex; gap: var(--space-4); margin-bottom: var(--space-4); flex-wrap: wrap; align-items: center;">
        <span class="card-meta"><strong>${summary.total}</strong> pending</span>
        ${summary.critical ? `<span class="card-meta" style="color: var(--danger);"><strong>${summary.critical}</strong> critical</span>` : ''}
        ${summary.warning ? `<span class="card-meta" style="color: #ea580c;"><strong>${summary.warning}</strong> warning</span>` : ''}
        <span class="card-meta"><strong>${summary.iberian}</strong> Iberian</span>
        <span class="card-meta"><strong>${summary.european}</strong> European</span>
      </div>
      <div class="toolbar" style="margin-bottom: var(--space-4);">
        <div class="toolbar-filters" style="display: flex; gap: var(--space-2); flex-wrap: wrap; align-items: center;">
          ${priorityPills.map(p => `<button type="button" class="filter-pill ${state.priorityFilter === p.key ? 'active' : ''}" data-priority="${p.key}">${p.label}</button>`).join('')}
          <span style="color: var(--hairline); margin: 0 var(--space-1);">|</span>
          ${zonePills.map(p => `<button type="button" class="filter-pill ${state.zoneFilter === p.key ? 'active' : ''}" data-zone="${p.key}">${p.label}</button>`).join('')}
          <span style="color: var(--hairline); margin: 0 var(--space-1);">|</span>
          ${daysPills.map(p => `<button type="button" class="filter-pill ${state.daysFilter === p.key ? 'active' : ''}" data-days="${p.key}">${p.label}</button>`).join('')}
          <span style="color: var(--hairline); margin: 0 var(--space-1);">|</span>
          <select id="alert-sort" style="font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline); background: var(--surface);">
            ${sortOptions.map(o => `<option value="${o.key}" ${state.sortBy === o.key ? 'selected' : ''}>${o.label}</option>`).join('')}
          </select>
          <span style="color: var(--hairline); margin: 0 var(--space-1);">|</span>
          <button type="button" class="filter-pill ${isGroup ? 'active' : ''}" data-view="group" title="Group by priority">☰ Group</button>
          <button type="button" class="filter-pill ${state.view === 'grid' ? 'active' : ''}" data-view="grid" title="Grid view">⊞ Grid</button>
          <button type="button" class="filter-pill ${state.view === 'list' ? 'active' : ''}" data-view="list" title="List view">☰ List</button>
        </div>
      </div>
      ${state.loading ? `<div class="empty-state"><p class="empty-state-text">Loading alerts...</p></div>` : list.length === 0 ? `<div class="empty-state"><p class="empty-state-text">No alerts match the current filters.</p></div>` : isGroup ? renderGroupView(list) : (state.view === 'grid' ? `<div class="card-grid">${list.map(alertCard).join('')}</div>` : `<table class="data-table"><thead><tr><th>Days</th><th>Zone</th><th>Order</th><th>Piece</th><th>Customer</th><th>Fulfilled</th><th style="text-align:right;">Actions</th></tr></thead><tbody>${list.map(alertRow).join('')}</tbody></table>`)}
    </div>
  `;
}

async function resolveAlert(orderId, pieceId, action, note = null) {
  try {
    const res = await fetch('/api/proxy/admin/access-alerts/resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ order_id: orderId, piece_id: pieceId, action, note }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (data.ok) {
      const isNote = action === 'note_added';
      if (!isNote) {
        toast(action === 'issue_detected' ? 'Alert converted to incidence.' : 'Alert resolved.', 'success');
        if (window.updateAccessAlertBadge) window.updateAccessAlertBadge();
        if (window.updateIncidenceBadge) window.updateIncidenceBadge();
        loadAlerts();
      }
    } else {
      throw new Error(data.error || 'Unknown error');
    }
  } catch (err) {
    toast(err.message || 'Failed to resolve alert.', 'error');
  }
}

function openConfirmModal({ title, message, detail, confirmText, confirmClass = 'btn-danger', requireType = null, showNote = false, onConfirm }) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 480px;">
      <p class="modal-title">${escapeHtml(title)}</p>
      <div style="margin-bottom: var(--space-3);">
        <p>${escapeHtml(message)}</p>
        ${detail ? `<p class="card-meta" style="margin-top:var(--space-2);">${escapeHtml(detail)}</p>` : ''}
        ${showNote ? `
          <div style="margin-top: var(--space-3);">
            <p class="card-meta">Add a note (optional):</p>
            <textarea id="confirm-note" rows="2" placeholder="How was this resolved? Any details for the team..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);"></textarea>
          </div>
        ` : ''}
        ${requireType ? `
          <div style="margin-top: var(--space-3);">
            <p class="card-meta">Type <strong>${requireType}</strong> to proceed:</p>
            <input type="text" id="confirm-input" autocomplete="off" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline); margin-top: var(--space-1);" placeholder="Type here...">
          </div>
        ` : ''}
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel" id="confirm-cancel">Cancel</button>
        <button type="button" class="btn ${confirmClass}" data-action="confirm" id="confirm-ok" ${requireType ? 'disabled' : ''}>${escapeHtml(confirmText)}</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const cancelBtn = overlay.querySelector('#confirm-cancel');
  const okBtn = overlay.querySelector('#confirm-ok');
  const input = overlay.querySelector('#confirm-input');
  const noteArea = overlay.querySelector('#confirm-note');
  setTimeout(() => cancelBtn.focus(), 50);
  const close = () => overlay.remove();
  cancelBtn.addEventListener('click', close);
  if (requireType && input) {
    input.addEventListener('input', () => { okBtn.disabled = input.value.trim() !== requireType; });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !okBtn.disabled) { e.preventDefault(); const note = noteArea ? noteArea.value.trim() || null : null; close(); onConfirm(note); }
    });
  }
  okBtn.addEventListener('click', () => { const note = noteArea ? noteArea.value.trim() || null : null; close(); onConfirm(note); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

async function openContactModal(customerId, orderId) {
  let customerName = `Customer ${customerId}`;
  let customerEmail = '';
  try {
    const res = await fetch(`/api/proxy/admin/members/${customerId}/profile`);
    if (res.ok) {
      const data = await res.json();
      const p = data.profile || {};
      customerName = `${p.first_name || ''} ${p.last_name || ''}`.trim() || customerName;
      customerEmail = p.email || '';
    }
  } catch (e) { console.error('[AccessAlerts] failed to load profile:', e); }

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 480px;">
      <p class="modal-title">Contact client</p>
      <div style="margin-bottom: var(--space-3);">
        <p class="card-meta" style="font-size:var(--size-lg); font-weight:600;">${escapeHtml(customerName)}</p>
        ${customerEmail ? `<p class="card-meta">${escapeHtml(customerEmail)}</p>` : ''}
        <p class="card-meta">Order: ${escapeHtml(String(orderId))}</p>
      </div>
      <div class="field-grid" style="grid-template-columns: 1fr; gap: var(--space-3);">
        <textarea id="contact-note" rows="3" placeholder="Notes about the contact attempt..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);"></textarea>
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel" id="contact-cancel">Cancel</button>
        <button type="button" class="btn btn-primary" data-action="mark-attempted" id="contact-ok">Mark contact attempted</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  const cancelBtn = overlay.querySelector('#contact-cancel');
  const okBtn = overlay.querySelector('#contact-ok');
  setTimeout(() => cancelBtn.focus(), 50);
  cancelBtn.addEventListener('click', () => overlay.remove());
  okBtn.addEventListener('click', async () => {
    const note = overlay.querySelector('#contact-note').value.trim() || null;
    overlay.remove();
    await resolveAlert(orderId, null, 'contact_attempted', note);
  });
  const saveNoteBtn = overlay.querySelector('#alert-save-note');
  const noteInput = overlay.querySelector('#alert-note-input');
  let _saving = false;
  saveNoteBtn.addEventListener('click', async () => {
    if (_saving) return;
    const text = noteInput.value.trim();
    if (!text) { toast('Enter a note first.', 'error'); return; }
    _saving = true;
    saveNoteBtn.disabled = true;
    saveNoteBtn.textContent = 'Saving...';
    try {
      await resolveAlert(orderId, pieceId, 'note_added', text);
      noteInput.value = '';
      // Refrescar historial inmediatamente
      let freshHistory = [];
      try {
        freshHistory = await loadAlertHistory(customerId);
      } catch (e) {
        console.warn('[AccessAlerts] loadAlertHistory failed:', e);
      }
      const tagMatches = text.match(/#([\w-]+)/g);
      const newEntry = {
        action: 'note_added',
        order_id: orderId,
        piece_id: pieceId,
        note: text,
        tags: tagMatches ? tagMatches.map(t => t.slice(1)) : null,
        created_incidence_id: null,
        timestamp: new Date().toISOString()
      };
      freshHistory.unshift(newEntry);
      const historyContainer = overlay.querySelector('[data-history-container]');
      if (historyContainer) {
        historyContainer.innerHTML = '<p style="font-weight:600; font-size:var(--size-sm); margin-bottom:var(--space-2); color:var(--text);">History</p>' + historyHtml(freshHistory);
        const scrollDiv = historyContainer.querySelector('div[style*="overflow-y"]');
        if (scrollDiv) scrollDiv.scrollTop = 0;
      }
      // Nota guardada — feedback visual vía historial actualizado, sin toast intrusivo
    } catch (err) {
      console.error('[AccessAlerts] save note error:', err);
      toast(err.message || 'Failed to save note.', 'error');
    }
    _saving = false;
    saveNoteBtn.disabled = false;
    saveNoteBtn.textContent = 'Save note';
  });

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

async function loadHistory(customerId) {
  try {
    const res = await fetch(`/api/proxy/admin/members/${customerId}/access-alert-history`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.history || [];
  } catch (e) { console.error('[AccessAlerts] history load error:', e); return []; }
}

async function loadAlertHistory(customerId) {
  try {
    const res = await fetch(`/api/proxy/admin/members/${customerId}/access-alert-history`);
    if (!res.ok) return [];
    const data = await res.json();
    return data.history || [];
  } catch (e) {
    return [];
  }
}

function historyHtml(history) {
  if (!history || history.length === 0) {
    return '<p class="card-meta" style="font-style:italic; color: var(--muted);">No previous actions recorded.</p>';
  }
  const actionLabels = {
    verbal_confirmation: '✓ Marked verbal',
    issue_detected: '⚠️ Converted to incidence',
    magic_link_sent: '🔗 Magic link sent',
    contact_attempted: '📧 Contact attempted',
    note_added: '📝 Note added',
  };
  return `
    <div style="max-height: 200px; overflow-y: auto;">
      ${history.map(h => `
        <div style="padding: var(--space-2) 0; border-bottom: 1px solid var(--hairline);">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="card-meta">${actionLabels[h.action] || h.action}</span>
            <span class="card-meta">${timeAgo(h.timestamp)}</span>
          </div>
          ${h.note ? `<p class="card-meta" style="margin-top:var(--space-1); color: var(--text);">📝 ${escapeHtml(h.note)}</p>` : ''}
          ${h.tags && h.tags.length ? `<p class="card-meta" style="margin-top:var(--space-1);">${h.tags.map(t => `<span style="display:inline-block; padding:1px 6px; border-radius:10px; background:var(--hairline); font-size:var(--size-xs); margin-right:var(--space-1); color:var(--muted);">#${escapeHtml(t)}</span>`).join('')}</p>` : ''}
          ${h.created_incidence_id ? `<p class="card-meta" style="margin-top:var(--space-1);">→ Incidence: ${escapeHtml(h.created_incidence_id.slice(0,8))}...</p>` : ''}
        </div>
      `).join('')}
    </div>
  `;
}

async function openDetailModal(orderId, pieceId, customerId) {
  let alert = null;
  for (const zone of ['iberian', 'european']) {
    alert = state.alerts[zone].find(a => String(a.order_id) === String(orderId) && String(a.piece_id) === String(pieceId));
    if (alert) break;
  }
  if (!alert) return;

  const days = alert.days_since_fulfillment || 0;
  const p = PRIORITY_LEVELS[getPriority(days)];

  // Cargar perfil
  let customerName = '';
  let customerEmail = '';
  let customerPhone = '';
  let customerLang = '';
  try {
    const res = await fetch(`/api/proxy/admin/members/${customerId}/profile`);
    if (res.ok) {
      const data = await res.json();
      const prof = data.profile || {};
      customerName = `${prof.first_name || ''} ${prof.last_name || ''}`.trim();
      customerEmail = prof.email || '';
      customerPhone = prof.phone || '';
      customerLang = prof.language || '';
    }
  } catch (e) { console.error('[AccessAlerts] profile load error:', e); }

  // Fallback si no hay nombre
  if (!customerName) customerName = `Customer ${customerId}`;

  const history = await loadHistory(customerId);

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 540px;">
      <!-- Header con prioridad -->
      <div style="display:flex; align-items:center; gap:var(--space-2); margin-bottom:var(--space-3); padding-bottom:var(--space-2); border-bottom: 2px solid ${p.border};">
        <span style="font-size:var(--size-xl);">${p.icon}</span>
        <span style="font-weight:600; color:${p.textColor}; font-size:var(--size-base);">${p.label || 'NORMAL'}</span>
        <span class="card-meta">· ${days} days elapsed</span>
      </div>

      <!-- Cliente humanizado -->
      <div style="margin-bottom: var(--space-4);">
        <p style="font-size:var(--size-lg); font-weight:600; margin-bottom:var(--space-1);">${escapeHtml(customerName)}</p>
        <div style="display:flex; gap:var(--space-3); flex-wrap:wrap;">
          ${customerEmail ? `<p class="card-meta">📧 ${escapeHtml(customerEmail)}</p>` : ''}
          ${customerPhone ? `<p class="card-meta">📞 ${escapeHtml(customerPhone)}</p>` : ''}
          ${customerLang ? `<p class="card-meta">🌐 ${escapeHtml(customerLang.toUpperCase())}</p>` : ''}
        </div>
      </div>

      <!-- Datos de la alerta -->
      <div style="background:${p.bg}; border-left:4px solid ${p.border}; padding:var(--space-3); margin-bottom:var(--space-4); border-radius: 4px;">
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: var(--space-2);">
          <p class="card-meta">Order: <strong>${escapeHtml(String(orderId))}</strong></p>
          <p class="card-meta">Piece: <strong>${escapeHtml(String(pieceId))}</strong></p>
          <p class="card-meta">Fulfilled: ${fmtDate(alert.fulfillment_date)}</p>
          <p class="card-meta">Zone: ${escapeHtml(String(alert.shipping_zone || 'Unknown'))}</p>
          <p class="card-meta">Customer ID: ${escapeHtml(String(customerId))}</p>
        </div>
      </div>

      <!-- Historial -->
      <div style="margin-bottom: var(--space-4);" data-history-container>
        <p style="font-weight:600; font-size:var(--size-sm); margin-bottom:var(--space-2); color:var(--text);">History</p>
        ${historyHtml(history)}
      </div>

      <!-- Añadir nota -->
      <div style="margin-bottom: var(--space-4); padding: var(--space-3); background: var(--bg-elevated); border-radius: 4px;">
        <p style="font-weight:600; font-size:var(--size-sm); margin-bottom:var(--space-2); color:var(--text);">Add a note</p>
        <textarea id="alert-note-input" rows="2" placeholder="Cliente enfadado, llamar lunes... Use #tag for labels" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline); border-radius: 4px; resize: vertical;"></textarea>
        <div style="margin-top: var(--space-2); display: flex; justify-content: space-between; align-items: center;">
          <span class="card-meta">Tip: use #urgente or #llamar-lunes to add tags</span>
          <button type="button" class="btn btn-sm btn-primary" id="alert-save-note">Save note</button>
        </div>
      </div>

      <!-- Acciones -->
      <div class="modal-actions" style="flex-wrap: wrap; gap: var(--space-2);">
        <button type="button" class="btn btn-secondary" data-action="cancel" id="detail-cancel">Close</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="contact-client" data-order-id="${escapeHtml(String(orderId))}" data-piece-id="${escapeHtml(String(pieceId))}" data-customer-id="${escapeHtml(String(customerId))}">📧 Contact</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="mark-verbal" data-order-id="${escapeHtml(String(orderId))}" data-piece-id="${escapeHtml(String(pieceId))}">✓ Verbal</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="send-magic-link" data-order-id="${escapeHtml(String(orderId))}" data-piece-id="${escapeHtml(String(pieceId))}" data-customer-id="${escapeHtml(String(customerId))}">🔗 Magic link</button>
        <button type="button" class="btn btn-sm btn-danger" data-action="mark-issue" data-order-id="${escapeHtml(String(orderId))}" data-piece-id="${escapeHtml(String(pieceId))}">⚠️ Issue</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const cancelBtn = overlay.querySelector('#detail-cancel');
  setTimeout(() => cancelBtn.focus(), 50);
  cancelBtn.addEventListener('click', () => overlay.remove());

  overlay.querySelectorAll('[data-action="contact-client"]').forEach(btn => {
    btn.addEventListener('click', () => { overlay.remove(); openContactModal(btn.dataset.customerId, btn.dataset.orderId); });
  });

  overlay.querySelectorAll('[data-action="mark-verbal"]').forEach(btn => {
    btn.addEventListener('click', () => {
      overlay.remove();
      openConfirmModal({
        title: 'Mark as verbally confirmed?',
        message: 'This will remove the alert permanently.',
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Yes, remove alert',
        confirmClass: 'btn-danger',
        showNote: true,
        onConfirm: (note) => resolveAlert(btn.dataset.orderId, btn.dataset.pieceId, 'verbal_confirmation', note),
      });
    });
  });

  overlay.querySelectorAll('[data-action="send-magic-link"]').forEach(btn => {
    btn.addEventListener('click', () => {
      overlay.remove();
      openConfirmModal({
        title: 'Send magic link?',
        message: `Send magic link to ${escapeHtml(customerName)}?`,
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Send magic link',
        confirmClass: 'btn-primary',
        showNote: true,
        onConfirm: (note) => sendMagicLink(btn.dataset.customerId, btn.dataset.pieceId, note),
      });
    });
  });

  overlay.querySelectorAll('[data-action="mark-issue"]').forEach(btn => {
    btn.addEventListener('click', () => {
      overlay.remove();
      openConfirmModal({
        title: 'Convert to incidence?',
        message: 'This will create a permanent incidence and remove the alert. This action cannot be undone.',
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Convert to issue',
        confirmClass: 'btn-danger',
        showNote: true,
        requireType: 'CONFIRM',
        onConfirm: (note) => resolveAlert(btn.dataset.orderId, btn.dataset.pieceId, 'issue_detected', note),
      });
    });
  });

  const saveNoteBtn = overlay.querySelector('#alert-save-note');
  const noteInput = overlay.querySelector('#alert-note-input');
  let _saving = false;
  saveNoteBtn.addEventListener('click', async () => {
    if (_saving) return;
    const text = noteInput.value.trim();
    if (!text) { toast('Enter a note first.', 'error'); return; }
    _saving = true;
    saveNoteBtn.disabled = true;
    saveNoteBtn.textContent = 'Saving...';
    try {
      await resolveAlert(orderId, pieceId, 'note_added', text);
      noteInput.value = '';
      // Refrescar historial inmediatamente
      let freshHistory = [];
      try {
        freshHistory = await loadAlertHistory(customerId);
      } catch (e) {
        console.warn('[AccessAlerts] loadAlertHistory failed:', e);
      }
      const tagMatches = text.match(/#([\w-]+)/g);
      const newEntry = {
        action: 'note_added',
        order_id: orderId,
        piece_id: pieceId,
        note: text,
        tags: tagMatches ? tagMatches.map(t => t.slice(1)) : null,
        created_incidence_id: null,
        timestamp: new Date().toISOString()
      };
      freshHistory.unshift(newEntry);
      const historyContainer = overlay.querySelector('[data-history-container]');
      if (historyContainer) {
        historyContainer.innerHTML = '<p style="font-weight:600; font-size:var(--size-sm); margin-bottom:var(--space-2); color:var(--text);">History</p>' + historyHtml(freshHistory);
        const scrollDiv = historyContainer.querySelector('div[style*="overflow-y"]');
        if (scrollDiv) scrollDiv.scrollTop = 0;
      }
      // Nota guardada — feedback visual vía historial actualizado, sin toast intrusivo
    } catch (err) {
      console.error('[AccessAlerts] save note error:', err);
      toast(err.message || 'Failed to save note.', 'error');
    }
    _saving = false;
    saveNoteBtn.disabled = false;
    saveNoteBtn.textContent = 'Save note';
  });

  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

async function sendMagicLink(customerId, pieceId, note = null) {
  try {
    const res = await fetch('/api/proxy/admin/magic-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ customer_id: customerId, piece_id: pieceId }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    toast('Magic link sent.', 'success');
    await resolveAlert(null, pieceId, 'magic_link_sent', note);
  } catch (err) {
    toast(err.message || 'Failed to send magic link.', 'error');
  }
}

function wireEvents() {
  const root = document.getElementById('tab-root');
  if (!root) return;

  root.querySelectorAll('[data-priority]').forEach(btn => {
    btn.addEventListener('click', () => { state.priorityFilter = btn.dataset.priority; renderContent(); wireEvents(); });
  });
  root.querySelectorAll('[data-zone]').forEach(btn => {
    btn.addEventListener('click', () => { state.zoneFilter = btn.dataset.zone; renderContent(); wireEvents(); });
  });
  root.querySelectorAll('[data-days]').forEach(btn => {
    btn.addEventListener('click', () => { state.daysFilter = btn.dataset.days; renderContent(); wireEvents(); });
  });

  const sortSelect = root.querySelector('#alert-sort');
  if (sortSelect) {
    sortSelect.addEventListener('change', (e) => { state.sortBy = e.target.value; renderContent(); wireEvents(); });
  }

  root.querySelectorAll('[data-view]').forEach(btn => {
    btn.addEventListener('click', () => { state.view = btn.dataset.view; renderContent(); wireEvents(); });
  });

  root.querySelectorAll('.alert-card, .alert-row').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('button')) return;
      openDetailModal(el.dataset.orderId, el.dataset.pieceId, el.dataset.customerId);
    });
  });

  root.querySelectorAll('[data-action="contact-client"]').forEach(btn => {
    btn.addEventListener('click', (e) => { e.stopPropagation(); openContactModal(btn.dataset.customerId, btn.dataset.orderId); });
  });

  root.querySelectorAll('[data-action="mark-verbal"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openConfirmModal({
        title: 'Mark as verbally confirmed?',
        message: 'This will remove the alert permanently.',
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Yes, remove alert',
        confirmClass: 'btn-danger',
        showNote: true,
        onConfirm: (note) => resolveAlert(btn.dataset.orderId, btn.dataset.pieceId, 'verbal_confirmation', note),
      });
    });
  });

  root.querySelectorAll('[data-action="send-magic-link"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openConfirmModal({
        title: 'Send magic link?',
        message: 'Send magic link to this customer?',
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Send magic link',
        confirmClass: 'btn-primary',
        showNote: true,
        onConfirm: (note) => sendMagicLink(btn.dataset.customerId, btn.dataset.pieceId, note),
      });
    });
  });

  root.querySelectorAll('[data-action="mark-issue"]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openConfirmModal({
        title: 'Convert to incidence?',
        message: 'This will create a permanent incidence and remove the alert. This action cannot be undone.',
        detail: `Order ${btn.dataset.orderId} · Piece ${btn.dataset.pieceId}`,
        confirmText: 'Convert to issue',
        confirmClass: 'btn-danger',
        showNote: true,
        requireType: 'CONFIRM',
        onConfirm: (note) => resolveAlert(btn.dataset.orderId, btn.dataset.pieceId, 'issue_detected', note),
      });
    });
  });
}

export function render(root) {
  root.innerHTML = `<div class="empty-state"><p class="empty-state-text">Loading...</p></div>`;
  loadAlerts();
}