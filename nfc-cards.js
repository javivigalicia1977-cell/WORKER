import { fmtDateTime } from '/js/utils.js';

let state = {
  cards: [],
  loading: false,
  error: null,
  filter: 'all',
  search: '',
  selectedId: null,
  detail: null,
  detailLoading: false,
  detailError: null,
  modal: null,
  assignSearchResults: [],
  assignSearchLoading: false,
  lostReason: ''
};

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatUID(uid) {
  if (!uid || uid.length !== 14) return uid;
  return uid.match(/.{1,4}/g).join('-');
}

function statusBadge(status) {
  if (status === 'assigned') return '<span class="badge badge-success">Assigned</span>';
  if (status === 'unassigned') return '<span class="badge badge-neutral">Unassigned</span>';
  if (status === 'lost') return '<span class="badge badge-danger">Lost</span>';
  if (status === 'disabled') return '<span class="badge badge-muted">Disabled</span>';
  return '<span class="badge badge-neutral">' + escapeHtml(status) + '</span>';
}

function timeAgo(dateStr) {
  const d = new Date(dateStr);
  const now = new Date();
  const diff = Math.floor((now - d) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

/* ── Confirm modal (same as post-curation.js) ─────────────────────── */
function confirmModal(message, opts = {}) {
  return new Promise((resolve) => {
    const { confirmText = 'Confirm', cancelText = 'Cancel', title = 'Confirm' } = opts;
    let modal = document.getElementById('confirm-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'confirm-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }
    modal.innerHTML = `
      <div class="modal" style="max-width:400px;">
        <h2 class="modal-title">${title}</h2>
        <p class="modal-message">${message}</p>
        <div class="modal-actions" style="margin-top:var(--space-4);">
          <button class="btn btn-secondary" id="confirm-cancel">${cancelText}</button>
          <button class="btn btn-primary" id="confirm-ok">${confirmText}</button>
        </div>
      </div>
    `;
    modal.style.display = 'flex';
    const okBtn = modal.querySelector('#confirm-ok');
    const cancelBtn = modal.querySelector('#confirm-cancel');
    function cleanup() {
      modal.style.display = 'none';
      okBtn.onclick = null;
      cancelBtn.onclick = null;
    }
    okBtn.onclick = () => { cleanup(); resolve(true); };
    cancelBtn.onclick = () => { cleanup(); resolve(false); };
  });
}

async function loadCards() {
  state.loading = true; state.error = null; renderContent(document.getElementById('nfc-root'));
  try {
    const res = await fetch('/api/proxy/admin/nfc-cards/list');
    if (!res.ok) throw new Error('Failed to load cards');
    state.cards = (await res.json()).cards || [];
  } catch (e) {
    state.error = e.message;
  } finally {
    state.loading = false; renderContent(document.getElementById('nfc-root'));
  }
}

async function loadDetail(uid) {
  state.selectedId = uid;
  state.detail = null; state.detailLoading = true; state.detailError = null;
  renderContent(document.getElementById('nfc-root'));
  try {
    const res = await fetch('/api/proxy/admin/nfc-cards/' + uid);
    if (!res.ok) throw new Error('Failed to load detail');
    state.detail = await res.json();
  } catch (e) {
    state.detailError = e.message;
  } finally {
    state.detailLoading = false; renderContent(document.getElementById('nfc-root'));
  }
}

async function assignCard(uid, customerId) {
  const res = await fetch('/api/proxy/admin/nfc-cards/' + uid + '/assign?customer_id=' + customerId, { method: 'POST' });
  if (!res.ok) throw new Error('Assign failed');
  closeModal(); await loadCards(); await loadDetail(uid);
}

async function unassignCard(uid) {
  const ok = await confirmModal('Unassign this card from the customer?', {
    confirmText: 'Unassign',
    cancelText: 'Cancel',
    title: 'Confirm unassign'
  });
  if (!ok) return;
  const res = await fetch('/api/proxy/admin/nfc-cards/' + uid + '/unassign', { method: 'POST' });
  if (!res.ok) throw new Error('Unassign failed');
  await loadCards(); await loadDetail(uid);
}

async function markLostCard(uid, reason) {
  const res = await fetch('/api/proxy/admin/nfc-cards/' + uid + '/mark-lost', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason })
  });
  if (!res.ok) throw new Error('Mark lost failed');
  closeModal(); state.lostReason = ''; await loadCards(); await loadDetail(uid);
}

async function searchCustomers(query) {
  state.assignSearchLoading = true; state.assignSearchResults = [];
  renderContent(document.getElementById('nfc-root'));
  try {
    const res = await fetch('/api/proxy/admin/customers/search?q=' + encodeURIComponent(query));
    if (!res.ok) throw new Error('Search failed');
    state.assignSearchResults = (await res.json()).customers || [];
  } catch (e) {
    console.error(e);
  } finally {
    state.assignSearchLoading = false; renderContent(document.getElementById('nfc-root'));
  }
}

function getFilteredCards() {
  let list = state.cards;
  if (state.filter !== 'all') list = list.filter(c => c.status === state.filter);
  if (state.search.trim()) {
    const q = state.search.trim().toLowerCase();
    list = list.filter(c =>
      (c.uid && c.uid.toLowerCase().includes(q)) ||
      (c.customer_name && c.customer_name.toLowerCase().includes(q)) ||
      (c.customer_email && c.customer_email.toLowerCase().includes(q))
    );
  }
  return list;
}

function getStatusCounts() {
  const counts = { all: state.cards.length, assigned: 0, unassigned: 0, lost: 0, disabled: 0 };
  for (const c of state.cards) { if (counts[c.status] !== undefined) counts[c.status]++; }
  return counts;
}

function renderToolbar(counts) {
  const filters = [
    { key: 'all', label: 'All' },
    { key: 'assigned', label: 'Assigned' },
    { key: 'unassigned', label: 'Unassigned' },
    { key: 'lost', label: 'Lost' },
    { key: 'disabled', label: 'Disabled' }
  ];
  let html = '<div class="toolbar">';
  html += '<div class="toolbar-filters">';
  for (const f of filters) {
    const active = state.filter === f.key ? ' active' : '';
    html += '<button type="button" class="btn-filter' + active + '" data-filter="' + f.key + '">' +
      f.label + ' (' + (counts[f.key] || 0) + ')' +
    '</button>';
  }
  html += '</div>';
  html += '<div class="toolbar-actions">';
  html += '<input type="text" id="nfc-search" class="toolbar-search" placeholder="Search UID or customer..." value="' + escapeHtml(state.search) + '">';
  html += '<button type="button" class="btn btn-sm btn-secondary" data-action="refresh">Refresh</button>';
  html += '</div>';
  html += '</div>';
  return html;
}

function renderListItem(card) {
  const isActive = card.uid === state.selectedId;
  const customerText = card.customer_name
    ? escapeHtml(card.customer_name) + (card.customer_id ? ' (#' + card.customer_id + ')' : '')
    : '<span class="text-muted">Unassigned</span>';
  return '<div class="split-list-item' + (isActive ? ' active' : '') + '" data-uid="' + card.uid + '">' +
    '<div class="col-mono">' + formatUID(card.uid) + '</div>' +
    '<div class="mt-2">' + statusBadge(card.status) + '</div>' +
    '<div class="mt-2 text-sm">' + customerText + '</div>' +
    '<div class="card-meta mt-2">' +
      (card.taps_count || 0) + ' taps' + (card.last_tap_at ? ' | ' + timeAgo(card.last_tap_at) : '') +
    '</div>' +
  '</div>';
}

function renderTapHistoryItem(tap) {
  return '<div class="nfc-timeline-item">' +
    '<div class="nfc-timeline-dot ' + (tap.allowed ? 'success' : 'denied') + '"></div>' +
    '<div>' +
      '<div class="text-sm">' + escapeHtml(tap.location || 'Unknown') + '</div>' +
      '<div class="card-meta">' + fmtDateTime(tap.created_at) + (tap.allowed ? '' : ' — Denied') + '</div>' +
    '</div>' +
  '</div>';
}

function renderDetail() {
  if (state.detailLoading) return '<div class="placeholder">Loading card...</div>';
  if (state.detailError) return '<div class="placeholder text-danger">Error: ' + state.detailError + '</div>';
  if (!state.detail) return '<div class="placeholder">Select a card to view details.</div>';

  const d = state.detail;
  const card = d.card || {};
  const customer = d.customer || null;
  const taps = d.tap_history || [];

  let html = '<div class="card-header">' +
    '<div class="card-title">' + formatUID(card.uid) + '</div>' +
    statusBadge(card.status) +
  '</div>';

  if (customer) {
    html += '<p class="card-meta">' +
      escapeHtml((customer.first_name || '') + ' ' + (customer.last_name || '')) + ' | ' + escapeHtml(customer.email || '-') +
    '</p>';
  } else {
    html += '<p class="card-meta text-muted">Not assigned to any customer</p>';
  }

  html += '<p class="card-meta">Created: ' + fmtDateTime(card.created_at) + '</p>';

  if (card.lost_reason) {
    html += '<div class="alert alert-danger">' +
      '<strong>Lost reason:</strong> ' + escapeHtml(card.lost_reason) +
    '</div>';
  }

  html += '<div class="section-heading">Tap history (' + taps.length + ')</div>';
  if (taps.length > 0) {
    html += '<div class="checklist">' + taps.map(renderTapHistoryItem).join('') + '</div>';
  } else {
    html += '<div class="placeholder">No tap history yet.</div>';
  }

  html += '<div class="section-heading">Metadata</div>' +
    '<div class="card-meta">' +
      'Key version: ' + (card.key_version || 'v1') + '<br>' +
      'Total taps: ' + (card.taps_count || 0) + '<br>' +
      'Last tap: ' + (card.last_tap_at ? timeAgo(card.last_tap_at) : 'Never') +
    '</div>';

  html += '<div class="section-heading">Actions</div>' +
    '<div class="flex-row-wrap mt-2">';

  if (card.status === 'unassigned') {
    html += '<button type="button" class="btn btn-primary" data-action="assign">Assign to customer</button>';
  }
  if (card.status === 'assigned') {
    html += '<button type="button" class="btn btn-danger" data-action="unassign">Unassign</button>';
    html += '<button type="button" class="btn btn-warning" data-action="mark-lost">Mark as lost</button>';
  }
  if (card.status === 'lost') {
    html += '<button type="button" class="btn btn-primary" data-action="restore">Restore</button>';
  }

  html += '<button type="button" class="btn btn-secondary ml-auto is-disabled" disabled title="Coming soon">Regenerate keys</button>';
  html += '</div>';

  return html;
}

function renderAssignModal() {
  if (state.modal !== 'assign') return '';
  const uid = state.selectedId;
  return '<div class="modal-overlay" onclick="if(event.target===this){closeModal()}">' +
    '<div class="modal modal-lg" role="dialog" aria-modal="true">' +
      '<p class="modal-title">Assign card ' + formatUID(uid) + '</p>' +
      '<div class="mb-3">' +
        '<input type="text" id="assign-search" class="form-input mb-3" placeholder="Search customer by name or email...">' +
        '<div id="assign-results">' +
          (state.assignSearchLoading ? '<div class="placeholder">Searching...</div>' : '') +
          (state.assignSearchResults.length === 0 && !state.assignSearchLoading ? '<div class="placeholder">Type 2+ characters to search</div>' : '') +
          state.assignSearchResults.map(function(c) {
            return '<div class="split-list-item cursor-pointer" data-assign-customer="' + c.customer_id + '">' +
              '<div>' + escapeHtml(c.first_name + ' ' + c.last_name) + '</div>' +
              '<div class="card-meta">' + escapeHtml(c.email || '-') + ' | #' + c.customer_id + '</div>' +
            '</div>';
          }).join('') +
        '</div>' +
      '</div>' +
      '<div class="flex-end">' +
        '<button type="button" class="btn btn-secondary" data-action="close-modal">Cancel</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function renderLostModal() {
  if (state.modal !== 'lost') return '';
  const uid = state.selectedId;
  const canSubmit = state.lostReason.trim().length >= 5;
  return '<div class="modal-overlay" onclick="if(event.target===this){closeModal()}">' +
    '<div class="modal modal-lg" role="dialog" aria-modal="true">' +
      '<p class="modal-title">Mark card ' + formatUID(uid) + ' as lost</p>' +
      '<div class="mb-3">' +
        '<textarea id="lost-reason" class="form-textarea" placeholder="Where/when lost, customer report, etc.">' + escapeHtml(state.lostReason) + '</textarea>' +
        '<p class="card-meta mt-1">' + (canSubmit ? 'Ready to submit' : 'Minimum 5 characters required') + '</p>' +
      '</div>' +
      '<div class="flex-end">' +
        '<button type="button" class="btn btn-secondary" data-action="close-modal">Cancel</button>' +
        '<button type="button" class="btn btn-danger" data-action="submit-lost"' + (canSubmit ? '' : ' disabled') + '>Mark as lost</button>' +
      '</div>' +
    '</div>' +
  '</div>';
}

function renderEmptyState() {
  const filtered = getFilteredCards();
  if (state.loading) return '<div class="placeholder">Loading cards...</div>';
  if (state.error) return '<div class="placeholder text-danger">' + state.error + '</div>';
  if (state.cards.length === 0) {
    return '<div class="empty-state">' +
      '<div class="empty-state-icon">&#9675;</div>' +
      '<h3 class="empty-state-title">No cards issued yet</h3>' +
      '<p class="card-meta">Cards appear here after programming.</p>' +
    '</div>';
  }
  if (filtered.length === 0) {
    let msg = 'No cards match the current filters.';
    if (state.filter === 'unassigned') msg = 'All cards are assigned.';
    if (state.filter === 'lost') msg = 'No lost cards. Clean sheet.';
    if (state.filter === 'disabled') msg = 'No disabled cards.';
    return '<div class="empty-state">' +
      '<div class="empty-state-icon">&#9675;</div>' +
      '<h3 class="empty-state-title">' + msg + '</h3>' +
    '</div>';
  }
  return filtered.map(renderListItem).join('');
}

function closeModal() {
  state.modal = null; state.assignSearchResults = []; state.assignSearchLoading = false;
  renderContent(document.getElementById('nfc-root'));
}

function attachEvents(root) {
  root.querySelectorAll('[data-filter]').forEach(el => {
    el.addEventListener('click', () => { state.filter = el.dataset.filter; renderContent(root); });
  });
  root.querySelectorAll('[data-uid]').forEach(el => {
    el.addEventListener('click', () => { if (!el.dataset.assignCustomer) loadDetail(el.dataset.uid); });
  });
  const searchInput = root.querySelector('#nfc-search');
  if (searchInput) {
    let t; searchInput.addEventListener('input', e => {
      clearTimeout(t); t = setTimeout(() => { state.search = e.target.value; renderContent(root); }, 300);
    });
    searchInput.addEventListener('keydown', e => { if (e.key === 'Escape') { state.search = ''; renderContent(root); } });
  }
  root.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', () => {
      const action = el.dataset.action;
      if (action === 'refresh') loadCards();
      if (action === 'assign') { state.modal = 'assign'; renderContent(root); }
      if (action === 'unassign') unassignCard(state.selectedId);
      if (action === 'mark-lost') { state.modal = 'lost'; renderContent(root); }
      if (action === 'restore') {
        fetch('/api/proxy/admin/nfc-cards/' + state.selectedId + '/restore', { method: 'POST' })
          .then(() => loadCards()).then(() => loadDetail(state.selectedId));
      }
      if (action === 'close-modal') closeModal();
      if (action === 'submit-lost') {
        const reason = root.querySelector('#lost-reason').value.trim();
        if (reason.length >= 5) markLostCard(state.selectedId, reason);
      }
    });
  });
  const assignSearch = root.querySelector('#assign-search');
  if (assignSearch) {
    let t; assignSearch.addEventListener('input', e => {
      clearTimeout(t); const q = e.target.value.trim();
      t = setTimeout(() => { if (q.length >= 2) searchCustomers(q); }, 300);
    });
    assignSearch.focus();
  }
  root.querySelectorAll('[data-assign-customer]').forEach(el => {
    el.addEventListener('click', () => assignCard(state.selectedId, el.dataset.assignCustomer));
  });
  const lostReason = root.querySelector('#lost-reason');
  if (lostReason) {
    lostReason.addEventListener('input', e => {
      state.lostReason = e.target.value; renderContent(root);
    });
    lostReason.focus();
  }
}

function renderContent(root) {
  const counts = getStatusCounts();
  let html = '<div class="split-layout">';
  html += '<div class="split-list">' + renderToolbar(counts) + renderEmptyState() + '</div>';
  html += '<div>' + renderDetail() + '</div>';
  html += '</div>';
  html += renderAssignModal();
  html += renderLostModal();
  root.innerHTML = html;
  attachEvents(root);
}

export function render(root, subPath) {
  root.innerHTML = '<div id="nfc-root"></div>';
  loadCards();
}
