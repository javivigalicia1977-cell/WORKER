// suppliers-view.js — v1.3 (C.5-B.3) — Alineado schema v6.12.4
// Backend: v6.12.3+ con schema extendido (id auto-generado, todos los campos del plan)

import { LABELS, label } from '/js/stock-labels.js?v=1';
import { toast, confirmModal } from '/js/ui.js?v=2';

/* ═══════════════════════════════════════════════════════════════════
   MODULE STATE
   ═══════════════════════════════════════════════════════════════════ */

let state = {
  view: 'list',
  selectedId: null,
  suppliers: [],
  filtered: [],
  filterType: 'all',
  searchQuery: '',
  isLoading: false,
  potisseId: 'potisse-in-house'
};

const SPECIALTY_SUGGESTIONS = ['embroidery', 'cutting', 'pressing', 'printing', 'sewing', 'packing', 'blanks', 'fabric', 'other'];
const SUPPLIER_TYPES = ['supplier', 'artisan_external', 'artisan_internal', 'both'];

/* ── helpers ─────────────────────────────────────── */

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function getAdminKey() {
  return new URLSearchParams(window.location.search).get('admin') || '';
}

async function api(path, options = {}) {
  const key = getAdminKey();
  // Usar worker directo — el proxy no reenvía /stock/*
  const url = `https://nfc.potisse.com/api/admin/stock${path}${key ? (path.includes('?') ? '&' : '?') + 'admin=' + encodeURIComponent(key) : ''}`;

  // Si es POST/PUT/DELETE, pedir TOTP
  const method = options.method || 'GET';
  if (method !== 'GET' && method !== 'HEAD') {
    const totp = prompt('Código TOTP:');
    if (!totp) throw new Error('TOTP requerido');
    options.headers = options.headers || {};
    options.headers['X-TOTP-Code'] = totp.trim();
  }

  const res = await fetch(url, options);
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'unknown' }));
    throw new Error(data.detail || data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function typeChip(type) {
  return `<span class="tag" style="background:var(--potisse-cream-dark);color:var(--potisse-chocolate);font-size:var(--size-xs);padding:2px 8px;">${escapeHtml(label('supplier_type.' + type) || type)}</span>`;
}

function statusChip(active) {
  const color = active !== false ? 'var(--success)' : 'var(--danger)';
  const text = active !== false ? 'Activo' : 'Inactivo';
  return `<span class="tag" style="background:${color}15;color:${color};font-size:var(--size-xs);padding:2px 8px;">${text}</span>`;
}

function renderTags(tags, max = 3) {
  if (!tags || !tags.length) return '';
  const visible = tags.slice(0, max);
  const hidden = tags.length > max ? tags.length - max : 0;
  let html = visible.map(t => `<span class="tag" style="background:var(--border);color:var(--text-muted);font-size:var(--size-xs);padding:2px 6px;margin-right:4px;">${escapeHtml(t)}</span>`).join('');
  if (hidden) html += `<span class="tag" style="background:var(--border);color:var(--text-muted);font-size:var(--size-xs);padding:2px 6px;" title="${escapeHtml(tags.slice(max).join(', '))}">+${hidden}</span>`;
  return html;
}

/* ═══════════════════════════════════════════════════════════════════
   EXPORTS
   ═══════════════════════════════════════════════════════════════════ */

export function renderSuppliersView() {
  if (state.view === 'list') return renderListView();
  if (state.view === 'detail') return renderDetailView();
  if (state.view === 'create') return renderFormView();
  if (state.view === 'edit') return renderFormView(state.selectedId);
  return renderListView();
}

export function initSuppliers(root) {
  if (state.view === 'list') initListEvents(root);
  else if (state.view === 'detail') initDetailEvents(root);
  else if (state.view === 'create' || state.view === 'edit') initFormEvents(root);
}

export function setInitialState(opts) {
  if (opts.view) state.view = opts.view;
  if (opts.selectedId) state.selectedId = opts.selectedId;
}

/* ═══════════════════════════════════════════════════════════════════
   LIST VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderListView() {
  return `
    <div id="suppliers-list-view">
      <div class="toolbar" style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-4);">
        <div class="toolbar-filters" style="display:flex;gap:var(--space-1);flex-wrap:wrap;">
          <button type="button" class="filter-pill${state.filterType === 'all' ? ' active' : ''}" data-filter="all">Todos</button>
          <button type="button" class="filter-pill${state.filterType === 'supplier' ? ' active' : ''}" data-filter="supplier">${LABELS.supplier}</button>
          <button type="button" class="filter-pill${state.filterType === 'artisan_external' ? ' active' : ''}" data-filter="artisan_external">${LABELS.artisan} ext.</button>
          <button type="button" class="filter-pill${state.filterType === 'artisan_internal' ? ' active' : ''}" data-filter="artisan_internal">${LABELS.artisan} int.</button>
          <button type="button" class="filter-pill${state.filterType === 'both' ? ' active' : ''}" data-filter="both">Ambos</button>
          <button type="button" class="filter-pill${state.filterType === 'inactive' ? ' active' : ''}" data-filter="inactive">Inactivos</button>
        </div>
        <div style="flex:1;min-width:200px;">
          <input type="text" id="sup-search" placeholder="Buscar por nombre, email, empresa..." value="${escapeHtml(state.searchQuery)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
        </div>
        <button type="button" class="btn btn-primary" id="sup-btn-create">${LABELS.create} ${LABELS.supplier}</button>
        <button type="button" class="btn btn-secondary" id="sup-btn-refresh">${LABELS.refresh}</button>
      </div>
      <div id="suppliers-list-content">
        ${state.isLoading ? '<p style="color:var(--muted);padding:var(--space-4);">Cargando...</p>' : renderSupplierRows()}
      </div>
    </div>
  `;
}

function renderSupplierRows() {
  applyFilters();
  const rows = state.filtered;
  if (!rows.length) {
    return `
      <div class="empty-state" style="text-align:center;padding:var(--space-8);">
        <div style="font-size:3em;opacity:0.3;margin-bottom:var(--space-3);">◯</div>
        <h3 style="margin:0;font-weight:500;color:var(--text);">${LABELS.empty_no_suppliers}</h3>
        <p style="margin-top:var(--space-2);font-size:var(--size-sm);color:var(--muted);">Añade Edgar (Pima Blanks), Teresa, artesanos chinos NFC...</p>
        <button type="button" class="btn btn-primary" id="sup-btn-bootstrap" style="margin-top:var(--space-4);">Bootstrap POTISSE In-house</button>
      </div>
    `;
  }

  return rows.map(s => {
    const isPotisse = s.id === state.potisseId;
    const potisseBadge = isPotisse ? `<span class="tag" style="background:var(--potisse-chocolate);color:#fff;font-size:var(--size-xs);padding:2px 8px;margin-left:8px;">In-house</span>` : '';
    const leadText = s.standard_lead_time_days != null ? `${LABELS.standard_lead_time}: ${s.standard_lead_time_days}d` : '';
    return `
      <div class="card" data-supplier-id="${escapeHtml(s.id)}" style="display:flex;align-items:flex-start;gap:var(--space-3);padding:var(--space-3);cursor:pointer;margin-bottom:var(--space-2);border:1px solid var(--border);">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:var(--space-1);flex-wrap:wrap;">
            <strong style="font-size:var(--size-md);color:var(--text);">${escapeHtml(s.name)}</strong>
            ${potisseBadge}
            ${s.type ? typeChip(s.type) : ''}
            ${statusChip(s.active)}
          </div>
          <div style="margin-top:var(--space-1);font-size:var(--size-sm);color:var(--muted);">
            ${s.company ? escapeHtml(s.company) : ''}${s.company && s.country_code ? ' · ' : ''}${s.country_code ? escapeHtml(s.country_code) : ''}
          </div>
          <div style="margin-top:var(--space-1);font-size:var(--size-sm);">
            ${s.email ? `<a href="mailto:${escapeHtml(s.email)}" style="color:var(--potisse-chocolate);" onclick="event.stopPropagation();">${escapeHtml(s.email)}</a>` : ''}
            ${s.email && s.phone ? ' · ' : ''}
            ${s.phone ? `<a href="tel:${escapeHtml(s.phone)}" style="color:var(--potisse-chocolate);" onclick="event.stopPropagation();">${escapeHtml(s.phone)}</a>` : ''}
          </div>
          <div style="margin-top:var(--space-2);">${renderTags(s.specialities)}</div>
          ${leadText ? `<div style="margin-top:var(--space-1);font-size:var(--size-xs);color:var(--text-muted);">${leadText}</div>` : ''}
        </div>
        <div style="flex-shrink:0;align-self:center;font-size:var(--size-lg);color:var(--muted);">→</div>
      </div>
    `;
  }).join('');
}

function applyFilters() {
  let rows = [...state.suppliers];
  rows.sort((a, b) => {
    if (a.id === state.potisseId) return -1;
    if (b.id === state.potisseId) return 1;
    return (a.name || '').localeCompare(b.name || '');
  });

  if (state.filterType === 'inactive') {
    rows = rows.filter(s => s.active === false);
  } else if (state.filterType !== 'all') {
    rows = rows.filter(s => s.type === state.filterType && s.active !== false);
  } else {
    rows = rows.filter(s => s.active !== false);
  }

  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase();
    rows = rows.filter(s =>
      (s.name || '').toLowerCase().includes(q) ||
      (s.email || '').toLowerCase().includes(q) ||
      (s.company || '').toLowerCase().includes(q) ||
      (s.contact_name || '').toLowerCase().includes(q)
    );
  }
  state.filtered = rows;
}

/* ═══════════════════════════════════════════════════════════════════
   DETAIL VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderDetailView() {
  const s = state.suppliers.find(x => x.id === state.selectedId);
  if (!s) return renderListView();
  const isPotisse = s.id === state.potisseId;
  const deleteDisabled = isPotisse ? 'disabled title="POTISSE In-house no se puede eliminar"' : '';
  const deleteClass = isPotisse ? 'btn-secondary' : 'btn-danger';

  return `
    <div id="suppliers-detail-view">
      <div style="margin-bottom:var(--space-4);">
        <button type="button" class="btn btn-secondary" id="sup-btn-back" style="margin-bottom:var(--space-2);">← Volver a ${LABELS.suppliers}</button>
        <div style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;">
          <h2 style="margin:0;font-weight:500;">${escapeHtml(s.name)}</h2>
          ${isPotisse ? '<span class="tag" style="background:var(--potisse-chocolate);color:#fff;font-size:var(--size-xs);padding:2px 8px;">In-house</span>' : ''}
          ${s.type ? typeChip(s.type) : ''}
          ${statusChip(s.active)}
        </div>
      </div>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Información de contacto</h4>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:var(--space-2);">
          ${s.contact_name ? `<div><span style="color:var(--muted);font-size:var(--size-xs);">Contacto</span><div>${escapeHtml(s.contact_name)}</div></div>` : ''}
          ${s.company ? `<div><span style="color:var(--muted);font-size:var(--size-xs);">Empresa</span><div>${escapeHtml(s.company)}</div></div>` : ''}
          ${s.email ? `<div><span style="color:var(--muted);font-size:var(--size-xs);">Email</span><div><a href="mailto:${escapeHtml(s.email)}" style="color:var(--potisse-chocolate);">${escapeHtml(s.email)}</a></div></div>` : ''}
          ${s.phone ? `<div><span style="color:var(--muted);font-size:var(--size-xs);">Teléfono</span><div><a href="tel:${escapeHtml(s.phone)}" style="color:var(--potisse-chocolate);">${escapeHtml(s.phone)}</a></div></div>` : ''}
          ${s.address ? `<div style="grid-column:1/-1;"><span style="color:var(--muted);font-size:var(--size-xs);">Dirección</span><div>${escapeHtml(s.address)}</div></div>` : ''}
          ${s.country_code ? `<div><span style="color:var(--muted);font-size:var(--size-xs);">País</span><div>${escapeHtml(s.country_code)}</div></div>` : ''}
        </div>
      </div>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Especialidades</h4>
        <div>${renderTags(s.specialities, 10) || '<span style="color:var(--muted);font-size:var(--size-sm);">Sin especialidades registradas.</span>'}</div>
      </div>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Rendimiento</h4>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:var(--space-2);">
          <div><span style="color:var(--muted);font-size:var(--size-xs);">${LABELS.standard_lead_time}</span><div>${s.standard_lead_time_days != null ? s.standard_lead_time_days + ' días' : '-'}</div></div>
        </div>
        ${s.performance_notes ? `<div style="margin-top:var(--space-2);"><span style="color:var(--muted);font-size:var(--size-xs);">Notas</span><div style="white-space:pre-wrap;">${escapeHtml(s.performance_notes)}</div></div>` : ''}
        <p style="margin-top:var(--space-2);font-size:var(--size-xs);color:var(--muted);font-style:italic;">Estadísticas reales de rendimiento se calcularán cuando existan lotes procesados.</p>
      </div>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Comunicaciones</h4>
        <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;">
          <button type="button" class="btn btn-primary" id="sup-btn-email">Enviar email</button>
          <button type="button" class="btn btn-secondary" disabled title="Próximamente">Registrar llamada</button>
        </div>
        <p style="margin-top:var(--space-2);font-size:var(--size-xs);color:var(--muted);">Historial de comunicaciones disponible en próxima versión (C.5-B.4).</p>
      </div>

      <div style="display:flex;gap:var(--space-2);margin-top:var(--space-4);">
        <button type="button" class="btn btn-primary" id="sup-btn-edit">${LABELS.edit}</button>
        <button type="button" class="btn ${deleteClass}" id="sup-btn-delete" ${deleteDisabled}>${LABELS.delete}</button>
      </div>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   FORM VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderFormView(editId = null) {
  const isEdit = !!editId;
  const s = isEdit ? state.suppliers.find(x => x.id === editId) : null;
  const isPotisse = isEdit && editId === state.potisseId;
  const title = isEdit ? `Editar ${LABELS.supplier}` : `${LABELS.create} ${LABELS.supplier}`;
  const values = {
    name: s?.name || '',
    contact_name: s?.contact_name || '',
    company: s?.company || '',
    email: s?.email || '',
    phone: s?.phone || '',
    address: s?.address || '',
    country_code: s?.country_code || '',
    type: s?.type || 'supplier',
    specialities: (s?.specialities || []).join(', '),
    standard_lead_time_days: s?.standard_lead_time_days != null ? s.standard_lead_time_days : 7,
    performance_notes: s?.performance_notes || ''
  };
  const typeDisabled = isPotisse ? 'disabled' : '';
  const typeTooltip = isPotisse ? 'title="Type de POTISSE In-house es protegido"' : '';

  return `
    <div id="suppliers-form-view">
      <h2 style="margin:0 0 var(--space-4) 0;font-weight:500;">${title}</h2>
      <form id="sup-form" style="max-width:700px;">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--space-3);margin-bottom:var(--space-4);">
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Nombre *</label>
            <input type="text" name="name" value="${escapeHtml(values.name)}" required minlength="2" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Persona de contacto</label>
            <input type="text" name="contact_name" value="${escapeHtml(values.contact_name)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Empresa</label>
            <input type="text" name="company" value="${escapeHtml(values.company)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Email *</label>
            <input type="email" name="email" value="${escapeHtml(values.email)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Teléfono</label>
            <input type="tel" name="phone" value="${escapeHtml(values.phone)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Código país (2 letras)</label>
            <input type="text" name="country_code" value="${escapeHtml(values.country_code)}" maxlength="2" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;text-transform:uppercase;">
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Dirección</label>
            <textarea name="address" rows="3" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;resize:vertical;">${escapeHtml(values.address)}</textarea>
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Tipo *</label>
            <select name="type" required ${typeDisabled} ${typeTooltip} style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;background:#fff;">
              ${SUPPLIER_TYPES.map(t => `<option value="${t}"${values.type === t ? ' selected' : ''}${isPotisse && t !== 'artisan_internal' ? ' disabled' : ''}>${escapeHtml(label('supplier_type.' + t) || t)}</option>`).join('')}
            </select>
          </div>
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">${LABELS.standard_lead_time} (días) *</label>
            <input type="number" name="standard_lead_time_days" value="${values.standard_lead_time_days}" required min="1" max="90" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Especialidades (separadas por coma)</label>
            <input type="text" name="specialities" value="${escapeHtml(values.specialities)}" placeholder="ej: embroidery, cutting, pressing" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
            <div style="margin-top:var(--space-1);">
              <span style="font-size:var(--size-xs);color:var(--muted);">Sugeridas:</span>
              ${SPECIALTY_SUGGESTIONS.map(tag => `<button type="button" class="tag-suggest" data-tag="${tag}" style="background:var(--border);color:var(--text-muted);font-size:var(--size-xs);padding:2px 6px;margin-right:4px;border:none;cursor:pointer;">${tag}</button>`).join('')}
            </div>
          </div>
          <div style="grid-column:1/-1;">
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Notas de rendimiento</label>
            <textarea name="performance_notes" rows="4" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;resize:vertical;">${escapeHtml(values.performance_notes)}</textarea>
          </div>
        </div>
        <div id="sup-form-errors" style="color:var(--danger);font-size:var(--size-sm);margin-bottom:var(--space-3);"></div>
        <div style="display:flex;gap:var(--space-2);">
          <button type="submit" class="btn btn-primary">${LABELS.save}</button>
          <button type="button" class="btn btn-secondary" id="sup-btn-cancel">${LABELS.cancel}</button>
        </div>
      </form>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   EVENT HANDLERS
   ═══════════════════════════════════════════════════════════════════ */

function initListEvents(root) {
  root.querySelectorAll('button[data-filter]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      state.filterType = e.currentTarget.dataset.filter;
      refreshList(root);
    });
  });

  const searchInput = root.querySelector('#sup-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      refreshList(root);
    });
  }

  root.querySelector('#sup-btn-create')?.addEventListener('click', () => {
    state.view = 'create';
    state.selectedId = null;
    refreshContent(root);
  });

  root.querySelector('#sup-btn-refresh')?.addEventListener('click', () => loadSuppliers(root));
  root.querySelector('#sup-btn-bootstrap')?.addEventListener('click', () => doBootstrap(root));

  root.querySelectorAll('.card[data-supplier-id]').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      state.view = 'detail';
      state.selectedId = card.dataset.supplierId;
      refreshContent(root);
    });
  });
}

function initDetailEvents(root) {
  root.querySelector('#sup-btn-back')?.addEventListener('click', () => {
    state.view = 'list';
    state.selectedId = null;
    refreshContent(root);
  });

  root.querySelector('#sup-btn-edit')?.addEventListener('click', () => {
    state.view = 'edit';
    refreshContent(root);
  });

  root.querySelector('#sup-btn-delete')?.addEventListener('click', async () => {
    const s = state.suppliers.find(x => x.id === state.selectedId);
    if (!s || s.id === state.potisseId) return;
    const confirmed = await confirmModal('Eliminar proveedor', `¿Eliminar a "${s.name}"? Esta acción desactiva el proveedor.`, 'Eliminar', true);
    if (!confirmed) return;
    try {
      await api(`/suppliers/${encodeURIComponent(s.id)}`, { method: 'DELETE' });
      toast('Proveedor eliminado.');
      state.view = 'list';
      state.selectedId = null;
      await loadSuppliers(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  root.querySelector('#sup-btn-email')?.addEventListener('click', () => {
    const s = state.suppliers.find(x => x.id === state.selectedId);
    if (!s || !s.email) return;
    openEmailModal(s);
  });
}

function initFormEvents(root) {
  root.querySelectorAll('.tag-suggest').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const input = root.querySelector('input[name="specialities"]');
      const tag = e.currentTarget.dataset.tag;
      const current = input.value.split(',').map(t => t.trim()).filter(Boolean);
      if (!current.includes(tag)) {
        current.push(tag);
        input.value = current.join(', ');
      }
    });
  });

  root.querySelector('#sup-btn-cancel')?.addEventListener('click', () => {
    state.view = state.selectedId ? 'detail' : 'list';
    refreshContent(root);
  });

  const form = root.querySelector('#sup-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errors = validateForm(form);
      const errDiv = root.querySelector('#sup-form-errors');
      if (errors.length) {
        errDiv.innerHTML = errors.map(err => `• ${err}`).join('<br>');
        return;
      }
      errDiv.innerHTML = '';

      const body = buildBodyFromForm(form);
      const isEdit = state.view === 'edit';
      try {
        if (isEdit) {
          await api(`/suppliers/${encodeURIComponent(state.selectedId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          toast('Proveedor actualizado.');
          state.view = 'detail';
        } else {
          const res = await api('/suppliers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          toast('Proveedor creado.');
          if (res && res.supplier && res.supplier.id) {
            state.selectedId = res.supplier.id;
            state.view = 'detail';
          } else {
            state.view = 'list';
            state.selectedId = null;
          }
        }
        await loadSuppliers(root);
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  }
}

/* ═══════════════════════════════════════════════════════════════════
   DATA OPERATIONS
   ═══════════════════════════════════════════════════════════════════ */

async function loadSuppliers(root) {
  state.isLoading = true;
  refreshList(root);
  try {
    const data = await api('/suppliers');
    state.suppliers = data.suppliers || [];
    state.isLoading = false;
    refreshList(root);
  } catch (err) {
    state.isLoading = false;
    toast(err.message, 'error');
    refreshList(root);
  }
}

async function doBootstrap(root) {
  try {
    await api('/suppliers/bootstrap', { method: 'POST' });
    toast('Sistema inicializado. POTISSE In-house creado.');
    await loadSuppliers(root);
  } catch (err) {
    toast(err.message, 'error');
  }
}

/* ═══════════════════════════════════════════════════════════════════
   VALIDATION & FORM BUILDER
   ═══════════════════════════════════════════════════════════════════ */

function validateForm(form) {
  const errors = [];
  const name = form.querySelector('[name="name"]').value.trim();
  const email = form.querySelector('[name="email"]').value.trim();
  const type = form.querySelector('[name="type"]').value;
  const leadTime = form.querySelector('[name="standard_lead_time_days"]').value;

  if (!name || name.length < 2) errors.push('El nombre debe tener al menos 2 caracteres.');
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('Email no válido.');
  if (!type) errors.push('El tipo es obligatorio.');
  if (!SUPPLIER_TYPES.includes(type)) errors.push('Tipo no válido.');
  if (!leadTime || Number(leadTime) <= 0) errors.push('El plazo de entrega debe ser mayor que 0.');

  return errors;
}

function buildBodyFromForm(form) {
  const get = (n) => {
    const el = form.querySelector(`[name="${n}"]`);
    return el ? el.value.trim() : '';
  };
  const getNum = (n) => {
    const el = form.querySelector(`[name="${n}"]`);
    if (!el) return null;
    const v = el.value.trim();
    return v ? Number(v) : null;
  };
  const specs = get('specialities').split(',').map(t => t.trim()).filter(Boolean);

  const body = {};
  body.name = get('name');
  body.email = get('email');
  body.type = get('type');
  body.standard_lead_time_days = getNum('standard_lead_time_days');

  const contact_name = get('contact_name');
  if (contact_name) body.contact_name = contact_name;

  const company = get('company');
  if (company) body.company = company;

  const phone = get('phone');
  if (phone) body.phone = phone;

  const address = get('address');
  if (address) body.address = address;

  const country_code = get('country_code').toUpperCase();
  if (country_code) body.country_code = country_code;

  if (specs.length) body.specialities = specs;

  const performance_notes = get('performance_notes');
  if (performance_notes) body.performance_notes = performance_notes;

  return body;
}

/* ═══════════════════════════════════════════════════════════════════
   EMAIL MODAL
   ═══════════════════════════════════════════════════════════════════ */

function openEmailModal(supplier) {
  let modal = document.getElementById('sup-email-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'sup-email-modal';
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
    <div class="modal" style="max-width:520px;">
      <h2 class="modal-title">Enviar email a ${escapeHtml(supplier.name)}</h2>
      <div style="margin-top:var(--space-3);">
        <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Asunto</label>
        <input type="text" id="sup-email-subject" value="[POTISSE] Consulta" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;">
      </div>
      <div style="margin-top:var(--space-2);">
        <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Cuerpo</label>
        <textarea id="sup-email-body" rows="10" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;resize:vertical;">Hola ${escapeHtml(supplier.contact_name || supplier.name)},

</textarea>
      </div>
      <p style="margin-top:var(--space-2);font-size:var(--size-xs);color:var(--muted);">Se abrirá tu cliente de email predeterminado con estos campos rellenados.</p>
      <div class="modal-actions" style="margin-top:var(--space-4);">
        <button type="button" class="btn btn-secondary" id="sup-email-cancel">Cancelar</button>
        <button type="button" class="btn btn-primary" id="sup-email-send">Abrir mailto:</button>
      </div>
    </div>
  `;
  modal.style.display = 'flex';

  const cancelBtn = modal.querySelector('#sup-email-cancel');
  const sendBtn = modal.querySelector('#sup-email-send');

  function cleanup() {
    modal.style.display = 'none';
  }

  cancelBtn.addEventListener('click', cleanup);
  sendBtn.addEventListener('click', () => {
    const subject = modal.querySelector('#sup-email-subject').value;
    const body = modal.querySelector('#sup-email-body').value;
    const mailto = `mailto:${encodeURIComponent(supplier.email)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    window.open(mailto, '_blank');
    cleanup();
  });

  modal.addEventListener('click', (e) => {
    if (e.target === modal) cleanup();
  });
}

/* ═══════════════════════════════════════════════════════════════════
   UI REFRESH HELPERS
   ═══════════════════════════════════════════════════════════════════ */

function refreshContent(root) {
  const container = root.querySelector('#stock-subtab-content');
  if (!container) return;
  container.innerHTML = renderSuppliersView();
  initSuppliers(root);
}

function refreshList(root) {
  const content = root.querySelector('#suppliers-list-content');
  if (content) content.innerHTML = renderSupplierRows();
  root.querySelectorAll('.card[data-supplier-id]').forEach(card => {
    card.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      state.view = 'detail';
      state.selectedId = card.dataset.supplierId;
      refreshContent(root);
    });
  });
}
