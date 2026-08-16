// batches-view.js — v2.0 (C.5-B.4b) — Activity Log + QC completos
// Backend: v6.12.7-stock-batches

import { LABELS, label } from '/js/stock-labels.js?v=3';
import { toast, confirmModal } from '/js/ui.js?v=2';

const BATCH_STATUSES = [
  'to_order', 'ordered', 'in_house', 'with_artisan',
  'qc_pending', 'stock_ready', 'discarded'
];

const STATUS_COLORS = {
  to_order:    '#6c757d',
  ordered:     '#0dcaf0',
  in_house:    '#0d6efd',
  with_artisan:'#ffc107',
  qc_pending:  '#fd7e14',
  stock_ready: '#198754',
  discarded:   '#adb5bd'
};

const ACTIVITY_COLORS = {
  note:           '#6c757d',
  transition:     '#0d6efd',
  email_sent:     '#0dcaf0',
  email_received: '#6610f2',
  call_log:       '#fd7e14',
  cost_logged:    '#198754',
  qc_result:      '#dc3545',
  alert:          '#ffc107',
  photo_attached: '#20c997'
};

const ACTIVITY_FILTER_TYPES = [
  { key: 'all', label: 'Todas' },
  { key: 'note', label: 'Notas' },
  { key: 'email_sent', label: 'Emails enviados' },
  { key: 'email_received', label: 'Emails recibidos' },
  { key: 'call_log', label: 'Llamadas' },
  { key: 'cost_logged', label: 'Costes' },
  { key: 'qc_result', label: 'QC' },
  { key: 'transition', label: 'Transiciones' },
  { key: 'alert', label: 'Alertas' }
];

const QC_DEFAULT_CHECKLIST = [
  { id: 'threads', label: 'Hilos sueltos / deshilachado' },
  { id: 'stains', label: 'Manchas o decoloracion' },
  { id: 'tears', label: 'Roturas o agujeros' },
  { id: 'embroidery', label: 'Bordado / logo correcto' },
  { id: 'size', label: 'Talla / medidas correctas' },
  { id: 'label', label: 'Etiqueta / branding' },
  { id: 'dimensions', label: 'Dimensiones generales' },
  { id: 'finish', label: 'Acabado general' }
];

const state = {
  view: 'list',
  selectedId: null,
  filterStatus: 'all',
  searchQuery: '',
  batches: [],
  items: [],
  suppliers: [],
  pipeline: {},
  isLoading: false,
  activityFilter: 'all'
};

function persistState() {}

async function api(path, options = {}) {
  const url = `/api/proxy/admin/stock${path}`;
  const res = await fetch(url, options);
  if (!res.ok) {
    let data;
    try { data = await res.json(); } catch { data = {}; }
    throw new Error(data.detail || data.error || data.message || `HTTP ${res.status}`);
  }
  return res.json();
}

export function renderBatchesView() {
  if (state.view === 'list') return renderListView();
  if (state.view === 'detail') return renderDetailView();
  if (state.view === 'create') return renderCreateView();
  return '<div>Error de vista</div>';
}

export async function initBatches(root) {
  state.view = 'list';
  state.selectedId = null;
  state.filterStatus = 'all';
  state.searchQuery = '';
  state.activityFilter = 'all';
  if (Object.keys(state.items).length === 0) await loadReferenceData(root);
  await refreshContent(root);
}

function renderListView() {
  const counts = state.pipeline || {};
  const pillStyle = (active) => `padding:0.3rem 0.8rem;border-radius:20px;border:1px solid #ddd;background:${active ? '#4a3b2a' : '#fff'};color:${active ? '#fff' : '#333'};cursor:pointer;font-size:0.85rem;`;
  return `
    <div id="batches-list-view">
      <div class="toolbar" style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-bottom:1rem;">
        <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
          <button type="button" class="filter-pill${state.filterStatus === 'all' ? ' active' : ''}" data-filter="all" style="${pillStyle(state.filterStatus === 'all')}">Todos (${counts.total || 0})</button>
          ${BATCH_STATUSES.map(s => `<button type="button" class="filter-pill${state.filterStatus === s ? ' active' : ''}" data-filter="${s}" style="${pillStyle(state.filterStatus === s)}">${escapeHtml(label(`batch_status.${s}`) || s)} (${counts[s] || 0})</button>`).join('')}
        </div>
        <div style="flex:1;min-width:200px;">
          <input type="text" id="batch-search" placeholder="Buscar por ID o notas..." value="${escapeHtml(state.searchQuery)}" style="width:100%;padding:0.4rem 0.6rem;border:1px solid #ddd;border-radius:4px;">
        </div>
        <button type="button" class="btn btn-primary" id="batch-btn-new">Nuevo lote</button>
        <button type="button" class="btn btn-secondary" id="batch-btn-refresh">Actualizar</button>
      </div>
      <div id="batches-list-content">
        ${renderBatchRows()}
      </div>
    </div>
  `;
}

function renderBatchRows() {
  let rows = state.batches;
  if (state.filterStatus !== 'all') {
    rows = rows.filter(b => b.status === state.filterStatus);
  }
  if (state.searchQuery) {
    const q = state.searchQuery.toLowerCase();
    rows = rows.filter(b => `${b.id} ${b.notes || ''}`.toLowerCase().includes(q));
  }
  if (rows.length === 0) {
    return `
      <div class="empty-state" style="text-align:center;padding:3rem;color:#888;">
        <div style="font-size:2.5rem;margin-bottom:0.5rem;">&#9675;</div>
        <p>${state.searchQuery || state.filterStatus !== 'all' ? LABELS.empty_filter_no_results : LABELS.empty_no_batches}</p>
        ${!state.searchQuery && state.filterStatus === 'all' ? `<button type="button" class="btn btn-primary" id="batch-btn-bootstrap">Nuevo lote</button>` : ''}
      </div>
    `;
  }
  return rows.map(b => `
    <div class="card" data-batch-id="${escapeHtml(b.id)}" style="padding:1rem;margin-bottom:0.75rem;border:1px solid #e9ecef;border-radius:6px;cursor:pointer;transition:box-shadow 0.15s;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;">
        <div>
          <code style="font-size:0.9rem;">${escapeHtml(b.id)}</code>
          <span class="badge" style="background:${STATUS_COLORS[b.status] || '#6c757d'};color:#fff;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.75rem;margin-left:0.5rem;">${escapeHtml(label(`batch_status.${b.status}`) || b.status)}</span>
        </div>
        <div style="font-size:0.85rem;color:#666;white-space:nowrap;">${b.quantity} ${b.item_unit || 'unid.'}</div>
      </div>
      <div style="margin-top:0.4rem;font-weight:500;">${escapeHtml(b.item_name || b.item_sku)}</div>
      ${b.current_holder_name ? `<div style="font-size:0.8rem;color:#666;margin-top:0.2rem;">&#128205; ${escapeHtml(b.current_holder_name)}</div>` : ''}
      <div style="font-size:0.8rem;color:#888;margin-top:0.3rem;display:flex;gap:1rem;">
        <span>Desde ${timeAgo(b.status_since)}</span>
        ${b.cost_accumulated > 0 ? `<span>Coste: ${b.cost_accumulated.toFixed(2)} ${b.currency}</span>` : ''}
      </div>
    </div>
  `).join('');
}

function renderDetailView() {
  const b = state.batches.find(x => x.id === state.selectedId);
  if (!b) return '<div>Lote no encontrado.</div>';

  const validTransitions = getValidTransitions(b.status);
  const allActivities = b.activities || [];

  return `
    <div id="batches-detail-view">
      <div style="margin-bottom:1rem;">
        <button type="button" class="btn btn-secondary" id="batch-btn-back">&larr; Volver a lotes</button>
      </div>
      <div class="card" style="padding:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
          <div>
            <code style="font-size:1.1rem;">${escapeHtml(b.id)}</code>
            <span class="badge" style="background:${STATUS_COLORS[b.status] || '#6c757d'};color:#fff;padding:0.2rem 0.6rem;border-radius:4px;font-size:0.8rem;margin-left:0.5rem;">${escapeHtml(label(`batch_status.${b.status}`) || b.status)}</span>
          </div>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
            ${validTransitions.length > 0 ? `<button type="button" class="btn btn-primary" id="batch-btn-transition">Cambiar estado</button>` : ''}
            <div class="dropdown" style="position:relative;">
              <button type="button" class="btn btn-secondary" id="batch-btn-activity-dropdown">+ Registrar actividad &#9660;</button>
              <div id="activity-dropdown-menu" style="display:none;position:absolute;right:0;top:100%;background:#fff;border:1px solid #ddd;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);z-index:100;min-width:200px;padding:0.3rem 0;">
                <button type="button" class="dropdown-item" data-activity="note" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#128221; Anadir nota</button>
                <button type="button" class="dropdown-item" data-activity="email-sent" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#128231; Email enviado</button>
                <button type="button" class="dropdown-item" data-activity="email-received" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#128232; Email recibido</button>
                <button type="button" class="dropdown-item" data-activity="call" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#128222; Llamada / mensaje</button>
                <button type="button" class="dropdown-item" data-activity="cost" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#128176; Coste</button>
                <button type="button" class="dropdown-item" data-activity="qc" style="display:block;width:100%;text-align:left;padding:0.5rem 1rem;border:none;background:none;cursor:pointer;font-size:0.9rem;">&#10003; Control de calidad</button>
              </div>
            </div>
            <button type="button" class="btn btn-danger" id="batch-btn-discard">Descartar</button>
          </div>
        </div>

        <div style="margin-top:1.2rem;">
          <h4 style="margin-bottom:0.5rem;">${escapeHtml(b.item_name || b.item_sku)}</h4>
          <div style="color:#666;">${b.quantity} ${b.item_unit || 'unid.'} &middot; Creado ${timeAgo(b.created_at)}</div>
        </div>

        <div style="margin-top:1.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.5rem;">
          <div>
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Informacion</h5>
            <div style="font-size:0.9rem;line-height:1.6;">
              <div><strong>SKU:</strong> ${escapeHtml(b.item_sku)}</div>
              <div><strong>Estado desde:</strong> ${timeAgo(b.status_since)}</div>
              ${b.expected_completion_at ? `<div><strong>ETA:</strong> ${formatDate(b.expected_completion_at)}</div>` : ''}
              ${b.notes ? `<div style="margin-top:0.5rem;color:#666;font-style:italic;">${escapeHtml(b.notes)}</div>` : ''}
            </div>
          </div>
          <div>
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Ubicacion</h5>
            <div style="font-size:0.9rem;line-height:1.6;">
              <div><strong>Responsable:</strong> ${escapeHtml(b.current_holder_name || '—')}</div>
              <div><strong>Paso:</strong> ${b.current_step_index + 1} / ${b.total_steps || '?'}</div>
              ${b.linked_po_id ? `<div><strong>PO:</strong> ${escapeHtml(b.linked_po_id)}</div>` : ''}
            </div>
          </div>
          <div>
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Coste & Genealogia</h5>
            <div style="font-size:0.9rem;line-height:1.6;">
              <div><strong>Coste acumulado:</strong> ${b.cost_accumulated?.toFixed(2) || '0.00'} ${b.currency}</div>
              ${(b.source_batch_ids || []).length > 0 ? `<div><strong>Origen:</strong> ${b.source_batch_ids.length} lote(s)</div>` : ''}
              ${(b.child_batch_ids || []).length > 0 ? `<div><strong>Hijos:</strong> ${b.child_batch_ids.length} lote(s)</div>` : ''}
              <button type="button" class="btn btn-sm btn-secondary" id="batch-btn-genealogy" style="margin-top:0.5rem;">${label('genealogy.view_tree') || 'Ver árbol de trazabilidad'}</button>
            </div>
          </div>
        </div>

        <div style="margin-top:1.5rem;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;flex-wrap:wrap;gap:0.5rem;">
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin:0;">Actividad completa (${allActivities.length})</h5>
            <div style="display:flex;gap:0.3rem;flex-wrap:wrap;">
              ${ACTIVITY_FILTER_TYPES.map(ft => {
                const active = state.activityFilter === ft.key;
                const count = ft.key === 'all' ? allActivities.length : allActivities.filter(a => a.type === ft.key).length;
                return `<button type="button" class="activity-filter-pill${active ? ' active' : ''}" data-filter="${ft.key}" style="padding:0.2rem 0.6rem;border-radius:12px;border:1px solid ${active ? ACTIVITY_COLORS[ft.key] || '#ddd' : '#ddd'};background:${active ? ACTIVITY_COLORS[ft.key] || '#f8f9fa' : '#fff'};color:${active ? '#fff' : '#666'};cursor:pointer;font-size:0.75rem;">${escapeHtml(ft.label)} (${count})</button>`;
              }).join('')}
            </div>
          </div>
          ${renderActivityTimeline(b)}
        </div>
      </div>
    </div>
  `;
}

function renderActivityTimeline(batch) {
  const activities = batch.activities || [];
  let filtered = activities;
  if (state.activityFilter !== 'all') {
    filtered = activities.filter(a => a.type === state.activityFilter);
  }
  const reversed = [...filtered].reverse();

  if (reversed.length === 0) {
    return `<div style="color:#888;font-size:0.9rem;padding:1rem 0;text-align:center;">${LABELS.empty_no_activities || 'Sin actividad registrada.'}</div>`;
  }

  return `
    <div id="activity-timeline" style="max-height:400px;overflow-y:auto;padding-right:0.5rem;">
      ${reversed.map(a => renderActivityEntry(a, batch.quantity)).join('')}
    </div>
  `;
}

function renderActivityEntry(a, batchQuantity) {
  const color = ACTIVITY_COLORS[a.type] || '#6c757d';
  const typeLabel = label(`activity_type.${a.type}`) || a.type;
  const time = timeAgo(a.timestamp);
  const actor = escapeHtml(a.actor || 'Sistema');

  let content = '';
  const d = a.data || {};

  switch (a.type) {
    case 'note':
      content = `<div style="color:#444;margin-top:0.3rem;white-space:pre-wrap;">${escapeHtml(d.text || '')}</div>`;
      break;
    case 'transition':
      content = `<div style="color:#444;margin-top:0.3rem;">&rarr; ${escapeHtml(label(`batch_status.${d.to_status}`) || d.to_status)}${d.new_holder_name ? ` &middot; Responsable: ${escapeHtml(d.new_holder_name)}` : ''}${d.note ? `<br><em>${escapeHtml(d.note)}</em>` : ''}</div>`;
      break;
    case 'email_sent':
      content = `
        <div style="color:#444;margin-top:0.3rem;">
          <div><strong>Para:</strong> ${escapeHtml(d.to_name || d.to || '—')}</div>
          <div><strong>Asunto:</strong> ${escapeHtml(d.subject || '—')}</div>
          ${d.body_preview ? `<div style="color:#666;margin-top:0.2rem;">${escapeHtml(d.body_preview)}</div>` : ''}
          ${d.forced ? `<span style="color:#dc3545;font-size:0.75rem;">&#9888; Forzado (guardrail)</span>` : ''}
        </div>`;
      break;
    case 'email_received':
      content = `
        <div style="color:#444;margin-top:0.3rem;">
          <div><strong>De:</strong> ${escapeHtml(d.from_name || d.from || '—')}</div>
          <div><strong>Asunto:</strong> ${escapeHtml(d.subject || '—')}</div>
          ${d.body_preview ? `<div style="color:#666;margin-top:0.2rem;">${escapeHtml(d.body_preview)}</div>` : ''}
        </div>`;
      break;
    case 'call_log':
      content = `
        <div style="color:#444;margin-top:0.3rem;">
          <div><strong>Medio:</strong> ${escapeHtml(label(`call_medium.${d.medium}`) || d.medium)}</div>
          <div><strong>Contacto:</strong> ${escapeHtml(d.contact_name || d.contact_id || '—')}</div>
          <div style="color:#666;margin-top:0.2rem;">${escapeHtml(d.summary || '')}</div>
          ${d.forced ? `<span style="color:#dc3545;font-size:0.75rem;">&#9888; Forzado (guardrail)</span>` : ''}
        </div>`;
      break;
    case 'cost_logged':
      content = `
        <div style="color:#444;margin-top:0.3rem;">
          <div><strong>Importe:</strong> ${d.amount?.toFixed(2)} ${d.currency || 'EUR'}</div>
          <div><strong>Concepto:</strong> ${escapeHtml(d.reason || '—')}</div>
          ${d.supplier_id ? `<div><strong>Proveedor:</strong> ${escapeHtml(d.supplier_id)}</div>` : ''}
        </div>`;
      break;
    case 'qc_result': {
      const qcColor = d.overall_pass ? '#198754' : '#dc3545';
      content = `
        <div style="color:#444;margin-top:0.3rem;">
          <div style="display:flex;gap:1rem;align-items:center;">
            <span style="font-size:1.2rem;font-weight:bold;color:${qcColor};">${d.passed}/${batchQuantity} OK</span>
            <span style="color:${qcColor};font-weight:500;">${d.overall_pass ? '&#10003; APROBADO' : '&#10007; RECHAZADO'}</span>
          </div>
          ${(d.checklist || []).length > 0 ? `
            <div style="margin-top:0.3rem;display:flex;flex-wrap:wrap;gap:0.3rem;">
              ${d.checklist.map(c => `<span style="padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;background:${c.pass ? '#d1e7dd' : '#f8d7da'};color:${c.pass ? '#0f5132' : '#842029'};">${escapeHtml(c.label || c.id)}</span>`).join('')}
            </div>
          ` : ''}
          ${d.notes ? `<div style="color:#666;margin-top:0.2rem;font-style:italic;">${escapeHtml(d.notes)}</div>` : ''}
        </div>`;
      break;
    }
    case 'alert':
      content = `<div style="color:#444;margin-top:0.3rem;">${escapeHtml(d.message || d.title || '')}</div>`;
      break;
    default:
      content = `<div style="color:#666;margin-top:0.3rem;font-size:0.85rem;"><pre style="margin:0;">${escapeHtml(JSON.stringify(d, null, 2))}</pre></div>`;
  }

  return `
    <div style="padding:0.75rem 0;border-bottom:1px solid #f0f0f0;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:0.5rem;">
        <div style="display:flex;align-items:center;gap:0.4rem;">
          <span style="padding:0.15rem 0.5rem;border-radius:12px;font-size:0.7rem;font-weight:600;background:${color};color:#fff;white-space:nowrap;">${escapeHtml(typeLabel)}</span>
          <span style="font-size:0.8rem;color:#666;">&middot; ${actor}</span>
        </div>
        <span style="color:#888;font-size:0.75rem;white-space:nowrap;">${time}</span>
      </div>
      ${content}
    </div>
  `;
}

function renderCreateView() {
  const itemOptions = Object.values(state.items || {})
    .filter(i => i.active !== false)
    .sort((a, b) => (a.name || a.sku).localeCompare(b.name || b.sku))
    .map(i => `<option value="${escapeHtml(i.sku)}">${escapeHtml(i.name || i.sku)} (${escapeHtml(i.sku)})</option>`)
    .join('');

  return `
    <div id="batches-create-view">
      <div style="margin-bottom:1rem;">
        <button type="button" class="btn btn-secondary" id="batch-btn-cancel">&larr; Cancelar</button>
      </div>
      <div class="card" style="padding:1.5rem;max-width:600px;">
        <h4>Nuevo lote</h4>
        <form id="batch-create-form" style="margin-top:1rem;">
          <div style="margin-bottom:1rem;">
            <label>Articulo *</label>
            <select name="item_sku" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">Seleccionar...</option>
              ${itemOptions}
            </select>
          </div>
          <div style="margin-bottom:1rem;">
            <label>Cantidad *</label>
            <input type="number" name="quantity" min="1" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:1rem;">
            <label>Notas</label>
            <textarea name="notes" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;"></textarea>
          </div>
          <div id="batch-form-errors" style="color:#dc3545;margin-bottom:1rem;font-size:0.9rem;"></div>
          <button type="submit" class="btn btn-primary">Crear lote</button>
          <button type="button" class="btn btn-secondary" id="batch-btn-cancel2">Cancelar</button>
        </form>
      </div>
    </div>
  `;
}

function initListEvents(root) {
  root.querySelectorAll('.filter-pill[data-filter]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.filterStatus = e.currentTarget.dataset.filter;
      refreshContent(root);
    });
  });

  const searchInput = root.querySelector('#batch-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      refreshList(root);
    });
  }

  root.querySelector('#batch-btn-new')?.addEventListener('click', () => {
    state.view = 'create';
    refreshContent(root);
  });

  root.querySelector('#batch-btn-refresh')?.addEventListener('click', async () => {
    await loadBatches(root);
    await loadPipeline(root);
    refreshContent(root);
  });

  root.querySelectorAll('.card[data-batch-id]').forEach(card => {
    card.addEventListener('click', async () => {
      state.view = 'detail';
      state.selectedId = card.dataset.batchId;
      await refreshContent(root);
    });
  });

  root.querySelector('#batch-btn-bootstrap')?.addEventListener('click', () => {
    state.view = 'create';
    refreshContent(root);
  });
}

function initDetailEvents(root) {
  root.querySelector('#batch-btn-back')?.addEventListener('click', async () => {
    state.view = 'list';
    state.selectedId = null;
    state.activityFilter = 'all';
    await refreshContent(root);
  });

  root.querySelector('#batch-btn-transition')?.addEventListener('click', () => {
    openTransitionModal(root);
  });

  const dropdownBtn = root.querySelector('#batch-btn-activity-dropdown');
  const dropdownMenu = root.querySelector('#activity-dropdown-menu');
  if (dropdownBtn && dropdownMenu) {
    dropdownBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = dropdownMenu.style.display === 'block';
      dropdownMenu.style.display = isOpen ? 'none' : 'block';
    });
    document.addEventListener('click', (e) => {
      if (!dropdownBtn.contains(e.target) && !dropdownMenu.contains(e.target)) {
        dropdownMenu.style.display = 'none';
      }
    });
    dropdownMenu.querySelectorAll('[data-activity]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        dropdownMenu.style.display = 'none';
        const type = btn.dataset.activity;
        openActivityModal(root, type);
      });
    });
  }

  root.querySelectorAll('.activity-filter-pill').forEach(btn => {
    btn.addEventListener('click', (e) => {
      state.activityFilter = e.target.dataset.filter;
      refreshContent(root);
    });
  });

  root.querySelector('#batch-btn-discard')?.addEventListener('click', async () => {
    const b = state.batches.find(x => x.id === state.selectedId);
    if (!b) return;
    if (!await confirmModal(`Descartar lote ${b.id}?`)) return;
    try {
      await api(`/batches/${encodeURIComponent(b.id)}/transition`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to_status: 'discarded' })
      });
      toast('Lote descartado.');
      state.view = 'list';
      state.selectedId = null;
      await refreshContent(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });

  root.querySelector('#batch-btn-genealogy')?.addEventListener('click', () => {
    openGenealogyModal(root, state.selectedId);
  });
}

function initCreateEvents(root) {
  const cancel = () => { state.view = 'list'; refreshContent(root); };
  root.querySelector('#batch-btn-cancel')?.addEventListener('click', cancel);
  root.querySelector('#batch-btn-cancel2')?.addEventListener('click', cancel);

  const form = root.querySelector('#batch-create-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const itemSku = form.querySelector('[name="item_sku"]').value.trim();
    const quantity = parseFloat(form.querySelector('[name="quantity"]').value);
    const notes = form.querySelector('[name="notes"]').value.trim();

    const errDiv = root.querySelector('#batch-form-errors');
    const errors = [];
    if (!itemSku) errors.push('Selecciona un articulo.');
    if (!quantity || quantity <= 0) errors.push('Cantidad debe ser mayor que 0.');

    if (errors.length) {
      errDiv.innerHTML = errors.map(err => `&bull; ${err}`).join('<br>');
      return;
    }
    errDiv.innerHTML = '';

    try {
      await api('/batches', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item_sku: itemSku, quantity, notes: notes || undefined })
      });
      toast('Lote creado.');
      state.filterStatus = 'all';
      state.searchQuery = '';
      state.view = 'list';
      state.selectedId = null;
      persistState();
      await refreshContent(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

function openActivityModal(root, type) {
  const b = state.batches.find(x => x.id === state.selectedId);
  if (!b) return;
  switch (type) {
    case 'note': openNoteModal(root, b); break;
    case 'email-sent': openEmailSentModal(root, b); break;
    case 'email-received': openEmailReceivedModal(root, b); break;
    case 'call': openCallModal(root, b); break;
    case 'cost': openCostModal(root, b); break;
    case 'qc': openQcModal(root, b); break;
  }
}

function openNoteModal(root, b) {
  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto;">
        <h4>&#128221; Anadir nota</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)}</p>
        <form id="activity-note-form">
          <div style="margin-bottom:1rem;">
            <label>Nota *</label>
            <textarea name="text" rows="4" required minlength="3" maxlength="500" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;resize:vertical;" placeholder="Escribe una nota sobre este lote..."></textarea>
            <div style="text-align:right;font-size:0.75rem;color:#888;margin-top:0.2rem;"><span id="note-char-count">0</span> / 500</div>
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Guardar nota</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  const textarea = document.querySelector('#activity-note-form [name="text"]');
  const counter = document.querySelector('#note-char-count');
  textarea.addEventListener('input', () => { counter.textContent = textarea.value.length; });

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = textarea.value.trim();
    if (text.length < 3 || text.length > 500) {
      toast('La nota debe tener entre 3 y 500 caracteres.', 'error');
      return;
    }
    try {
      await api(`/batches/${encodeURIComponent(b.id)}/activity/note`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      });
      toast('Nota guardada.');
      closeModal();
      await reloadBatchDetail(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

function openEmailSentModal(root, b) {
  const supplierOptions = Object.values(state.suppliers || {})
    .filter(s => s.active !== false)
    .map(s => `<option value="${escapeHtml(s.id)}" data-email="${escapeHtml(s.email || '')}" data-name="${escapeHtml(s.contact_name || s.name || '')}">${escapeHtml(s.name)}</option>`)
    .join('');

  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto;">
        <h4>&#128231; Email enviado</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)}</p>
        <form id="activity-email-sent-form">
          <div style="margin-bottom:0.75rem;">
            <label>Proveedor (opcional)</label>
            <select name="supplier_id" id="email-supplier-select" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">&mdash; Manual &mdash;</option>
              ${supplierOptions}
            </select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Destinatario *</label>
            <input type="email" name="to" id="email-to" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Nombre destinatario</label>
            <input type="text" name="to_name" id="email-to-name" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Asunto *</label>
            <input type="text" name="subject" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:1rem;">
            <label>Resumen del cuerpo</label>
            <textarea name="body_preview" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;resize:vertical;"></textarea>
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Registrar email</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  const supplierSelect = document.querySelector('#email-supplier-select');
  const toInput = document.querySelector('#email-to');
  const toNameInput = document.querySelector('#email-to-name');

  supplierSelect.addEventListener('change', () => {
    const opt = supplierSelect.options[supplierSelect.selectedIndex];
    if (opt.value) {
      toInput.value = opt.dataset.email || '';
      toNameInput.value = opt.dataset.name || '';
    }
  });

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-email-sent-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const payload = {
      to: form.querySelector('[name="to"]').value.trim(),
      to_name: form.querySelector('[name="to_name"]').value.trim() || null,
      supplier_id: form.querySelector('[name="supplier_id"]').value || null,
      subject: form.querySelector('[name="subject"]').value.trim(),
      body_preview: form.querySelector('[name="body_preview"]').value.trim() || null
    };
    if (!payload.to || !payload.subject) {
      toast('Destinatario y asunto son obligatorios.', 'error');
      return;
    }
    await submitActivity(root, b.id, 'email-sent', payload, 'Email registrado.');
  });
}

function openEmailReceivedModal(root, b) {
  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto;">
        <h4>&#128232; Email recibido</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)}</p>
        <form id="activity-email-received-form">
          <div style="margin-bottom:0.75rem;">
            <label>Remitente</label>
            <input type="email" name="from" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Nombre remitente</label>
            <input type="text" name="from_name" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Asunto</label>
            <input type="text" name="subject" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:1rem;">
            <label>Resumen del cuerpo</label>
            <textarea name="body_preview" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;resize:vertical;"></textarea>
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Registrar email</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-email-received-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const payload = {
      from: form.querySelector('[name="from"]').value.trim() || null,
      from_name: form.querySelector('[name="from_name"]').value.trim() || null,
      subject: form.querySelector('[name="subject"]').value.trim() || null,
      body_preview: form.querySelector('[name="body_preview"]').value.trim() || null
    };
    await submitActivity(root, b.id, 'email-received', payload, 'Email recibido registrado.');
  });
}

function openCallModal(root, b) {
  const contactOptions = Object.values(state.suppliers || {})
    .filter(s => s.active !== false)
    .map(s => `<option value="${escapeHtml(s.id)}" data-name="${escapeHtml(s.contact_name || s.name || '')}">${escapeHtml(s.name)}</option>`)
    .join('');

  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto;">
        <h4>&#128222; Llamada / mensaje</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)}</p>
        <form id="activity-call-form">
          <div style="margin-bottom:0.75rem;">
            <label>Medio *</label>
            <select name="medium" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">Seleccionar...</option>
              <option value="call">&#128222; Llamada telefonica</option>
              <option value="whatsapp">&#128172; WhatsApp</option>
              <option value="sms">&#128241; SMS</option>
              <option value="visit">&#127970; Visita en persona</option>
            </select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Contacto (proveedor)</label>
            <select name="contact_id" id="call-contact-select" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">&mdash; Manual &mdash;</option>
              ${contactOptions}
            </select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Nombre del contacto</label>
            <input type="text" name="contact_name" id="call-contact-name" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:1rem;">
            <label>Resumen *</label>
            <textarea name="summary" rows="3" required minlength="5" maxlength="500" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;resize:vertical;" placeholder="Resumen de la conversacion..."></textarea>
            <div style="text-align:right;font-size:0.75rem;color:#888;margin-top:0.2rem;"><span id="call-char-count">0</span> / 500</div>
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Registrar llamada</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  const contactSelect = document.querySelector('#call-contact-select');
  const contactNameInput = document.querySelector('#call-contact-name');
  contactSelect.addEventListener('change', () => {
    const opt = contactSelect.options[contactSelect.selectedIndex];
    if (opt.value) contactNameInput.value = opt.dataset.name || '';
  });

  const summaryArea = document.querySelector('#activity-call-form [name="summary"]');
  const counter = document.querySelector('#call-char-count');
  summaryArea.addEventListener('input', () => { counter.textContent = summaryArea.value.length; });

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-call-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const payload = {
      medium: form.querySelector('[name="medium"]').value,
      contact_id: form.querySelector('[name="contact_id"]').value || null,
      contact_name: form.querySelector('[name="contact_name"]').value.trim() || null,
      summary: form.querySelector('[name="summary"]').value.trim()
    };
    if (!payload.medium || !payload.summary) {
      toast('Medio y resumen son obligatorios.', 'error');
      return;
    }
    await submitActivity(root, b.id, 'call', payload, 'Llamada registrada.');
  });
}

function openCostModal(root, b) {
  const supplierOptions = Object.values(state.suppliers || {})
    .filter(s => s.active !== false)
    .map(s => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)}</option>`)
    .join('');

  const currentCost = b.cost_accumulated?.toFixed(2) || '0.00';

  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:500px;max-height:90vh;overflow-y:auto;">
        <h4>&#128176; Registrar coste</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)} &middot; Coste acumulado actual: <strong>${currentCost} ${b.currency}</strong></p>
        <form id="activity-cost-form">
          <div style="margin-bottom:0.75rem;">
            <label>Importe *</label>
            <input type="number" name="amount" step="0.01" min="0" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Moneda</label>
            <select name="currency" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="EUR" selected>EUR (&euro;)</option>
              <option value="USD">USD ($)</option>
              <option value="GBP">GBP (&pound;)</option>
            </select>
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Concepto *</label>
            <input type="text" name="reason" required placeholder="Ej: Transporte, materiales, mano de obra..." style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="margin-bottom:0.75rem;">
            <label>Proveedor asociado</label>
            <select name="supplier_id" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">&mdash; Ninguno &mdash;</option>
              ${supplierOptions}
            </select>
          </div>
          <div style="margin-bottom:1rem;">
            <label>Factura asociada</label>
            <input type="text" name="linked_invoice_id" placeholder="N de factura (opcional)" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Registrar coste</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-cost-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const amount = parseFloat(form.querySelector('[name="amount"]').value);
    if (isNaN(amount) || amount < 0) {
      toast('El importe debe ser un numero positivo.', 'error');
      return;
    }
    const payload = {
      amount,
      currency: form.querySelector('[name="currency"]').value,
      reason: form.querySelector('[name="reason"]').value.trim(),
      supplier_id: form.querySelector('[name="supplier_id"]').value || null,
      linked_invoice_id: form.querySelector('[name="linked_invoice_id"]').value.trim() || null
    };
    if (!payload.reason) {
      toast('El concepto es obligatorio.', 'error');
      return;
    }
    try {
      const res = await api(`/batches/${encodeURIComponent(b.id)}/activity/cost`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      toast(`Coste registrado. Nuevo total: ${res.cost_accumulated?.toFixed(2) || '?'} ${b.currency}`);
      closeModal();
      await reloadBatchDetail(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

function openQcModal(root, b) {
  const checklistItems = QC_DEFAULT_CHECKLIST.map((item) => `
    <div style="display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0;border-bottom:1px solid #f0f0f0;">
      <span style="flex:1;font-size:0.9rem;">${escapeHtml(item.label)}</span>
      <label style="display:flex;align-items:center;gap:0.2rem;cursor:pointer;font-size:0.85rem;">
        <input type="radio" name="qc-${item.id}" value="pass" checked> &#10003;
      </label>
      <label style="display:flex;align-items:center;gap:0.2rem;cursor:pointer;font-size:0.85rem;color:#dc3545;">
        <input type="radio" name="qc-${item.id}" value="fail"> &#10007;
      </label>
      <input type="text" placeholder="Notas" data-qc-note="${item.id}" style="width:120px;padding:0.2rem 0.4rem;border:1px solid #ddd;border-radius:4px;font-size:0.8rem;">
    </div>
  `).join('');

  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:600px;max-height:90vh;overflow-y:auto;">
        <h4>&#10003; Control de calidad</h4>
        <p style="color:#666;font-size:0.85rem;">${escapeHtml(b.id)} &middot; Total unidades: <strong>${b.quantity}</strong></p>
        <form id="activity-qc-form">
          <div style="margin-bottom:1rem;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
              <label style="font-weight:600;">Checklist</label>
              <button type="button" id="qc-add-custom" style="font-size:0.8rem;padding:0.2rem 0.5rem;background:#f8f9fa;border:1px solid #ddd;border-radius:4px;cursor:pointer;">+ Anadir punto</button>
            </div>
            <div id="qc-checklist-container">
              ${checklistItems}
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:0.75rem;">
            <div>
              <label>Unidades aprobadas *</label>
              <input type="number" name="passed" id="qc-passed" min="0" max="${b.quantity}" value="${b.quantity}" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
            </div>
            <div>
              <label>Unidades rechazadas *</label>
              <input type="number" name="failed" id="qc-failed" min="0" max="${b.quantity}" value="0" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
            </div>
          </div>
          <div id="qc-validation-error" style="color:#dc3545;font-size:0.85rem;margin-bottom:0.75rem;display:none;"></div>

          <div style="margin-bottom:1rem;">
            <label>Notas generales</label>
            <textarea name="notes" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;resize:vertical;"></textarea>
          </div>

          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Registrar QC</button>
          </div>
        </form>
      </div>
    </div>
  `;
  showModal(html);

  let customCount = 0;
  document.querySelector('#qc-add-custom').addEventListener('click', () => {
    customCount++;
    const container = document.querySelector('#qc-checklist-container');
    const div = document.createElement('div');
    div.style.cssText = 'display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0;border-bottom:1px solid #f0f0f0;';
    div.innerHTML = `
      <input type="text" placeholder="Nuevo punto de control" data-qc-custom-label="${customCount}" style="flex:1;padding:0.3rem 0.5rem;border:1px solid #ddd;border-radius:4px;font-size:0.9rem;" required>
      <label style="display:flex;align-items:center;gap:0.2rem;cursor:pointer;font-size:0.85rem;">
        <input type="radio" name="qc-custom-${customCount}" value="pass" checked> &#10003;
      </label>
      <label style="display:flex;align-items:center;gap:0.2rem;cursor:pointer;font-size:0.85rem;color:#dc3545;">
        <input type="radio" name="qc-custom-${customCount}" value="fail"> &#10007;
      </label>
      <button type="button" class="qc-remove-custom" style="background:none;border:none;color:#dc3545;cursor:pointer;font-size:1rem;">&times;</button>
    `;
    div.querySelector('.qc-remove-custom').addEventListener('click', () => div.remove());
    container.appendChild(div);
  });

  const passedInput = document.querySelector('#qc-passed');
  const failedInput = document.querySelector('#qc-failed');
  const errorDiv = document.querySelector('#qc-validation-error');
  const total = b.quantity;

  function validateQc() {
    const p = parseInt(passedInput.value) || 0;
    const f = parseInt(failedInput.value) || 0;
    if (p + f !== total) {
      errorDiv.textContent = `Aprobadas (${p}) + Rechazadas (${f}) deben sumar ${total}`;
      errorDiv.style.display = 'block';
      return false;
    }
    errorDiv.style.display = 'none';
    return true;
  }

  passedInput.addEventListener('input', validateQc);
  failedInput.addEventListener('input', validateQc);

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);
  document.querySelector('#activity-qc-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!validateQc()) return;

    const passed = parseInt(passedInput.value) || 0;
    const failed = parseInt(failedInput.value) || 0;

    const checklist = [];
    QC_DEFAULT_CHECKLIST.forEach(item => {
      const passVal = document.querySelector(`input[name="qc-${item.id}"]:checked`)?.value;
      const noteVal = document.querySelector(`[data-qc-note="${item.id}"]`)?.value;
      checklist.push({
        id: item.id,
        label: item.label,
        pass: passVal === 'pass',
        note: noteVal?.trim() || null
      });
    });
    document.querySelectorAll('[data-qc-custom-label]').forEach(input => {
      const idx = input.dataset.qcCustomLabel;
      const passVal = document.querySelector(`input[name="qc-custom-${idx}"]:checked`)?.value;
      if (input.value.trim()) {
        checklist.push({
          id: `custom_${idx}`,
          label: input.value.trim(),
          pass: passVal === 'pass',
          note: null
        });
      }
    });

    const payload = {
      passed,
      failed,
      total,
      checklist,
      notes: document.querySelector('#activity-qc-form [name="notes"]').value.trim() || null
    };

    try {
      await api(`/batches/${encodeURIComponent(b.id)}/activity/qc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const overallPass = failed === 0;
      if (overallPass) {
        toast(`QC aprobado: ${passed}/${total} unidades OK. Considera mover a "En stock".`, 'success');
      } else {
        toast(`QC rechazado: ${failed} unidades con defectos. Revisa el timeline.`, 'error');
      }
      closeModal();
      await reloadBatchDetail(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

async function submitActivity(root, batchId, endpointType, payload, successMsg) {
  const endpointMap = {
    'email-sent': '/activity/email-sent',
    'email-received': '/activity/email-received',
    'call': '/activity/call'
  };
  const endpoint = endpointMap[endpointType];
  if (!endpoint) {
    toast('Tipo de actividad desconocido.', 'error');
    return;
  }

  try {
    const res = await api(`/batches/${encodeURIComponent(batchId)}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.warning === 'recent_comm_exists') {
      const hours = res.hours_ago?.toFixed(1) || '?';
      const lastActor = res.last_comm?.actor || 'alguien';
      const lastType = label(`activity_type.${res.last_comm?.type}`) || res.last_comm?.type || 'comunicacion';
      const confirmed = await confirmModal(
        `Ya hay una ${lastType} reciente de ${lastActor} hace ${hours}h. Forzar registro?`,
        'Comunicacion reciente'
      );
      if (!confirmed) {
        closeModal();
        return;
      }
      const forceRes = await api(`/batches/${encodeURIComponent(batchId)}${endpoint}?force=1`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (forceRes.ok) {
        toast(successMsg + ' (forzado)');
        closeModal();
        await reloadBatchDetail(root);
      }
      return;
    }

    if (res.ok) {
      toast(successMsg);
      closeModal();
      await reloadBatchDetail(root);
    }
  } catch (err) {
    toast(err.message, 'error');
  }
}

function showModal(html) {
  closeModal();
  const modal = document.createElement('div');
  modal.id = 'batch-modal-wrapper';
  modal.innerHTML = html;
  document.body.appendChild(modal);
}

function closeModal() {
  document.querySelector('#batch-modal-wrapper')?.remove();
}

function openTransitionModal(root) {
  const b = state.batches.find(x => x.id === state.selectedId);
  if (!b) return;
  const valid = getValidTransitions(b.status);
  if (valid.length === 0) {
    toast('No hay transiciones disponibles.', 'info');
    return;
  }

  const options = valid.map(t => `<option value="${t}">${escapeHtml(label(`batch_status.${t}`) || t)}</option>`).join('');
  const holderOptions = Object.values(state.suppliers || {})
    .filter(s => s.active !== false)
    .map(s => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)}</option>`)
    .join('');

  const html = `
    <div id="batch-modal-overlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:1000;display:flex;align-items:center;justify-content:center;">
      <div style="background:#fff;padding:1.5rem;border-radius:8px;width:90%;max-width:420px;">
        <h4>Cambiar estado</h4>
        <p style="color:#666;font-size:0.9rem;">${escapeHtml(b.id)} &mdash; Actual: ${escapeHtml(label(`batch_status.${b.status}`) || b.status)}</p>
        <form id="batch-transition-form">
          <div style="margin-bottom:1rem;">
            <label>Nuevo estado *</label>
            <select name="to_status" required style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">Seleccionar...</option>
              ${options}
            </select>
          </div>
          <div style="margin-bottom:1rem;" id="batch-holder-field" style="display:none;">
            <label>Nuevo responsable</label>
            <select name="new_holder_id" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">&mdash; Sin cambio &mdash;</option>
              ${holderOptions}
            </select>
          </div>
          <div style="margin-bottom:1rem;">
            <label>Nota (opcional)</label>
            <textarea name="note" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;"></textarea>
          </div>
          <div style="display:flex;gap:0.5rem;justify-content:flex-end;">
            <button type="button" class="btn btn-secondary" id="batch-modal-cancel">Cancelar</button>
            <button type="submit" class="btn btn-primary">Confirmar</button>
          </div>
        </form>
      </div>
    </div>
  `;

  showModal(html);

  const form = document.querySelector('#batch-transition-form');
  const statusSelect = form.querySelector('[name="to_status"]');
  const holderField = document.querySelector('#batch-holder-field');

  statusSelect.addEventListener('change', () => {
    const needsHolder = ['with_artisan', 'in_house', 'ordered'].includes(statusSelect.value);
    holderField.style.display = needsHolder ? 'block' : 'none';
  });

  document.querySelector('#batch-modal-cancel').addEventListener('click', closeModal);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const toStatus = form.querySelector('[name="to_status"]').value;
    const newHolder = form.querySelector('[name="new_holder_id"]').value || null;
    const note = form.querySelector('[name="note"]').value.trim();

    try {
      await api(`/batches/${encodeURIComponent(b.id)}/transition`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to_status: toStatus, new_holder_id: newHolder, note: note || undefined })
      });
      toast(`Estado actualizado a ${label(`batch_status.${toStatus}`) || toStatus}.`);
      closeModal();
      await loadBatches(root);
      await refreshContent(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

async function reloadBatchDetail(root) {
  try {
    const data = await api(`/batches/${encodeURIComponent(state.selectedId)}`);
    const idx = state.batches.findIndex(b => b.id === state.selectedId);
    if (idx >= 0) {
      state.batches[idx] = data.batch || data;
    }
    await refreshContent(root);
  } catch (err) {
    toast(err.message, 'error');
  }
}

async function loadBatches(root) {
  state.isLoading = true;
  try {
    const data = await api('/batches');
    state.batches = data.batches || [];
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    state.isLoading = false;
  }
}

async function loadPipeline(root) {
  try {
    const data = await api('/pipeline-aggregate');
    state.pipeline = data.totals || {};
  } catch (err) {
    state.pipeline = {};
  }
}

async function loadReferenceData(root) {
  try {
    const [itemsData, suppliersData] = await Promise.all([
      api('/items'),
      api('/suppliers')
    ]);
    state.items = itemsData.items || {};
    state.suppliers = suppliersData.suppliers || {};
  } catch (err) {
    console.error('Error cargando datos de referencia:', err);
  }
}

async function refreshContent(root) {
  const container = root.querySelector('#stock-subtab-content');
  if (!container) return;
  if (state.view === 'list' && !state.isLoading) {
    await loadBatches(root);
    await loadPipeline(root);
  }
  if (state.view === 'detail' && state.selectedId) {
    await loadBatchDetail(state.selectedId);
  }
  container.innerHTML = renderBatchesView();
  if (state.view === 'list') initListEvents(root);
  else if (state.view === 'detail') initDetailEvents(root);
  else if (state.view === 'create') initCreateEvents(root);
}

async function loadBatchDetail(batchId) {
  try {
    const data = await api(`/batches/${encodeURIComponent(batchId)}`);
    const batch = data.batch || data;
    const idx = state.batches.findIndex(b => b.id === batchId);
    if (idx >= 0) {
      state.batches[idx] = batch;
    } else {
      state.batches.push(batch);
    }
  } catch (err) {
    console.error('Error cargando detalle del lote:', err);
  }
}

function refreshList(root) {
  const content = root.querySelector('#batches-list-content');
  if (content) content.innerHTML = renderBatchRows();
  root.querySelectorAll('.card[data-batch-id]').forEach(card => {
    card.addEventListener('click', async () => {
      state.view = 'detail';
      state.selectedId = card.dataset.batchId;
      await refreshContent(root);
    });
  });
  root.querySelector('#batch-btn-bootstrap')?.addEventListener('click', () => {
    state.view = 'create';
    refreshContent(root);
  });
}

function getValidTransitions(status) {
  const map = {
    to_order:      ['ordered', 'discarded'],
    ordered:       ['in_house', 'discarded'],
    in_house:      ['with_artisan', 'qc_pending', 'stock_ready', 'discarded'],
    with_artisan:  ['in_house', 'qc_pending', 'stock_ready', 'discarded'],
    qc_pending:    ['stock_ready', 'discarded', 'in_house'],
    stock_ready:   ['discarded'],
    discarded:     []
  };
  return map[status] || [];
}


async function openGenealogyModal(root, batchId) {
  try {
    const data = await api(`/batches/${encodeURIComponent(batchId)}/genealogy`);
    const { ancestors = [], descendants = [], root: rootBatch } = data;

    const renderNode = (n, isCurrent = false) => `
      <div style="margin:0.3rem 0;padding:0.4rem 0.6rem;border-radius:6px;background:${isCurrent?'#e7f1ff':'#f8f9fa'};border-left:3px solid ${isCurrent?'#0d6efd':(STATUS_COLORS[n.status]||'#6c757d')};">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span><code style="font-size:0.85rem;">${escapeHtml(n.id)}</code> ${escapeHtml(n.item_name || n.item_sku || '')} — ${n.quantity} uds</span>
          ${isCurrent ? `<span style="font-weight:600;color:#0d6efd;">${label('genealogy.current_marker')}</span>` : `<button type="button" class="btn btn-sm btn-secondary genealogy-nav" data-batch-id="${escapeHtml(n.id)}">Ver</button>`}
        </div>
        <div style="font-size:0.75rem;color:#666;">
          <span style="background:${STATUS_COLORS[n.status]||'#6c757d'};color:#fff;padding:0.1rem 0.3rem;border-radius:3px;">${label(`batch_status.${n.status}`)||n.status}</span>
          ${n.current_holder_name ? `· ${escapeHtml(n.current_holder_name)}` : ''}
        </div>
      </div>
    `;

    const renderTree = (nodes, direction) => {
      if (!nodes || nodes.length === 0) return `<div style="color:#888;font-style:italic;padding:0.5rem;">${label(direction==='ancestors'?'genealogy.no_ancestors':'genealogy.no_descendants')}</div>`;
      let html = '';
      nodes.forEach(n => {
        const indent = Math.min(n.depth || 0, 5) * 1.2;
        html += `<div style="margin-left:${indent}rem;">${renderNode(n)}</div>`;
      });
      return html;
    };

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true" style="max-width:700px;max-height:80vh;overflow:auto;">
        <p class="modal-title">${label('genealogy.title')}</p>
        <div style="margin-bottom:1rem;">
          <div style="font-weight:600;color:#888;margin-bottom:0.4rem;font-size:0.85rem;">${label('genealogy.ancestors_title')}</div>
          ${renderTree(ancestors, 'ancestors')}
        </div>
        <div style="margin:1rem 0;padding:0.75rem;background:#f0f7ff;border-radius:8px;border:2px solid #0d6efd;">
          <div style="font-weight:600;color:#0d6efd;margin-bottom:0.3rem;font-size:0.85rem;">LOTE ACTUAL</div>
          ${renderNode(rootBatch || { id: batchId }, true)}
        </div>
        <div style="margin-bottom:1rem;">
          <div style="font-weight:600;color:#888;margin-bottom:0.4rem;font-size:0.85rem;">${label('genealogy.descendants_title')}</div>
          ${renderTree(descendants, 'descendants')}
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" data-action="close">Cerrar</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelectorAll('.genealogy-nav').forEach(btn => {
      btn.addEventListener('click', () => {
        const bid = btn.dataset.batchId;
        overlay.remove();
        state.view = 'list';
        state.selectedId = bid;
        window.location.hash = `#/stock/batches?open=${encodeURIComponent(bid)}`;
      });
    });
    overlay.querySelector('[data-action="close"]').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

  } catch (err) {
    toast(err.message, 'error');
  }
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function timeAgo(iso) {
  if (!iso) return '&mdash;';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'ahora';
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  const days = Math.floor(hrs / 24);
  return `${days}d`;
}

function formatDate(iso) {
  if (!iso) return '&mdash;';
  const d = new Date(iso);
  return d.toLocaleDateString('es-ES');
}
