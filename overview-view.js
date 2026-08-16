// overview-view.js — v1.5 (C.5-B.5) — FIX: deduped + zero imports + window.* deps
// Backend: v6.12.7-stock-batches

const PO_STATUSES = ['draft', 'sent', 'confirmed', 'shipped', 'received', 'cancelled'];
const PO_STATUS_COLORS = {
  draft: '#6c757d', sent: '#0dcaf0', confirmed: '#198754',
  shipped: '#ffc107', received: '#0d6efd', cancelled: '#adb5bd'
};

const URGENCY_COLORS = {
  out_of_stock: '#dc3545', order_now: '#e67e22',
  order_soon: '#f1c40f', plan_to_order: '#0dcaf0', healthy: '#198754'
};

const BATCH_STATUSES_ORDER = ['to_order','ordered','in_house','with_artisan','qc_pending','stock_ready','discarded'];
const STATUS_COLORS = {
  to_order:'#6c757d', ordered:'#0dcaf0', in_house:'#0d6efd',
  with_artisan:'#ffc107', qc_pending:'#fd7e14', stock_ready:'#198754', discarded:'#adb5bd'
};

let state = {
  currentView: 'dashboard',
  selectedPoId: null,
  restockStatus: [],
  suggestedActions: [],
  pipelineAggregate: {},
  groupedRestock: [],
  pos: [],
  suppliers: [],
  items: [],
  poFilterStatus: 'all',
  poSearch: '',
  poSupplierFilter: '',
  _editingPo: null,
  _prefillSupplier: null,
  _prefillItems: null
};

/* ── helpers ─────────────────────────────────────── */

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

async function api(path, options = {}) {
  const url = `/api/proxy/admin/stock${path}`;
  const res = await fetch(url, options);
  if (!res.ok) {
    let data; try { data = await res.json(); } catch { data = {}; }
    throw new Error(data.detail || data.error || data.message || `HTTP ${res.status}`);
  }
  return res.json();
}

function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString('es-ES');
}

function formatCurrency(n, curr = 'EUR') {
  if (n == null) return '—';
  return `${Number(n).toFixed(2)} ${curr}`;
}

function timeAgo(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'ahora';
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

/* ── render principal ────────────────────────────── */

export function renderOverviewView() {
  if (state.currentView === 'dashboard') return renderDashboard();
  if (state.currentView === 'pos_list') return renderPoList();
  if (state.currentView === 'po_detail') return renderPoDetail();
  if (state.currentView === 'po_create') return renderPoCreate();
  return '<div>Error de vista</div>';
}

export async function initOverview(root) {
  if (state.currentView === 'dashboard') {
    root.innerHTML = '<div style="padding:3rem;text-align:center;color:#888;"><div style="font-size:2rem;margin-bottom:0.5rem;">◯</div>Cargando overview...</div>';
    await loadDashboardData();
    root.innerHTML = renderDashboard();
    initDashboardEvents(root);
  } else if (state.currentView === 'pos_list') {
    root.innerHTML = renderPoList();
    initPoListEvents(root);
  } else if (state.currentView === 'po_detail') {
    root.innerHTML = renderPoDetail();
    initPoDetailEvents(root);
  } else if (state.currentView === 'po_create') {
    root.innerHTML = renderPoCreate();
    initPoCreateEvents(root);
  }
}

/* ═══════════════════════════════════════════════════
   BLOQUE A — DASHBOARD
   ═══════════════════════════════════════════════════ */

function renderDashboard() {
  const restockUrgent = state.restockStatus.filter(r => ['out_of_stock','order_now'].includes(r.urgency_level));
  const poRecent = state.pos.slice(0, 5);

  const urgentCount = restockUrgent.length;
  const inactiveBatches = (state.pipelineAggregate?.alerts?.no_activity_48h || []).length;
  const qcPending = (state.pipelineAggregate?.counts?.qc_pending || 0);
  const posWaiting = state.pos.filter(p => p.status === 'sent').length;

  return `
    <div id="overview-dashboard">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:0.75rem;margin-bottom:1.5rem;">
        ${renderAlertCard('🔴', urgentCount, window.label('overview.alerts.urgent_items'), 'restock')}
        ${renderAlertCard('🟡', inactiveBatches, window.label('overview.alerts.inactive_batches'), 'batches')}
        ${renderAlertCard('🟢', qcPending, window.label('overview.alerts.qc_pending'), 'batches')}
        ${renderAlertCard('📨', posWaiting, window.label('overview.alerts.pos_waiting'), 'pos')}
      </div>

      <div class="card" style="padding:1.25rem;margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h4 style="margin:0;">${window.label('overview.restock_urgent_title')}</h4>
          <button type="button" class="btn btn-secondary" id="ov-btn-grouped-restock">${window.label('overview.create_grouped_po')}</button>
        </div>
        ${restockUrgent.length === 0 ? `<div style="color:#888;">${window.label('overview.no_urgent_today')}</div>` : `
          <table style="width:100%;font-size:0.9rem;border-collapse:collapse;">
            <thead><tr style="text-align:left;border-bottom:1px solid #ddd;">
              <th>Item</th><th>Categoría</th><th>Stock</th><th>Lead</th><th>Urgencia</th>
            </tr></thead>
            <tbody>
              ${restockUrgent.map(r => `
                <tr style="border-bottom:1px solid #eee;">
                  <td><code>${escapeHtml(r.item_sku)}</code> ${escapeHtml(r.item_name)}</td>
                  <td>${escapeHtml(r.category)}</td>
                  <td>${(r.current_stock ?? r.quantity) || 0} ${r.unit}</td>
                  <td>${r.lead_time_days}d</td>
                  <td><span style="background:${URGENCY_COLORS[r.urgency_level]||'#6c757d'};color:#fff;padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;">${window.label(`urgency.${r.urgency_level}`)||r.urgency_level}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        `}
      </div>

      <div class="card" style="padding:1.25rem;margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h4 style="margin:0;">${window.label('overview.suggested_actions_title')}</h4>
          <span style="font-size:0.85rem;color:#888;">${state.suggestedActions.length} total</span>
        </div>
        ${state.suggestedActions.length === 0 ? `<div style="color:#888;">${window.label('overview.no_urgent_today')}</div>` : `
          <div style="display:flex;flex-direction:column;gap:0.5rem;">
            ${state.suggestedActions.map(a => `
              <div style="display:flex;align-items:center;gap:0.75rem;padding:0.6rem;background:#f8f9fa;border-radius:6px;border-left:4px solid ${a.priority==='high'?'#dc3545':a.priority==='medium'?'#f1c40f':'#0dcaf0'};">
                <span style="font-size:1.2rem;">${a.type==='restock'?'📦':a.type==='qc'?'🔍':a.type==='po'?'📨':a.type==='batch'?'📋':'📌'}</span>
                <div style="flex:1;">
                  <div style="font-weight:500;">${escapeHtml(a.title)}</div>
                  <div style="font-size:0.8rem;color:#666;">${escapeHtml(a.description||'')}</div>
                </div>
                <button type="button" class="btn btn-sm btn-secondary ov-suggested-link" data-link="${escapeHtml(a.deep_link||'')}">Ir</button>
              </div>
            `).join('')}
          </div>
        `}
      </div>

      <div class="card" style="padding:1.25rem;margin-bottom:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h4 style="margin:0;">${window.label('overview.pipeline_snapshot_title')}</h4>
          <a href="#/stock/batches" class="btn btn-sm btn-secondary">Ver todos los lotes</a>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:0.5rem;margin-bottom:1rem;">
          ${BATCH_STATUSES_ORDER.map(s => {
            const count = state.pipelineAggregate.counts?.[s] || 0;
            return `<div style="text-align:center;padding:0.5rem;background:#f8f9fa;border-radius:6px;">
              <div style="font-size:1.4rem;font-weight:600;color:${STATUS_COLORS[s]};">${count}</div>
              <div style="font-size:0.75rem;color:#666;">${window.label(`batch_status.${s}`)||s}</div>
            </div>`;
          }).join('')}
        </div>
        ${renderPipelineAlerts()}
      </div>

      <div class="card" style="padding:1.25rem;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;">
          <h4 style="margin:0;">${window.label('overview.recent_pos_title')}</h4>
          <div style="display:flex;gap:0.5rem;">
            <button type="button" class="btn btn-sm btn-secondary" id="ov-btn-all-pos">${window.label('overview.view_all')}</button>
            <button type="button" class="btn btn-sm btn-primary" id="ov-btn-new-po">${window.label('overview.new_po')}</button>
          </div>
        </div>
        ${poRecent.length === 0 ? `<div style="color:#888;">${window.label('overview.no_pos_yet')}</div>` : renderPoMiniTable(poRecent)}
      </div>
    </div>
  `;
}

function renderAlertCard(icon, count, labelText, target) {
  return `<div class="card" style="padding:0.75rem;text-align:center;cursor:pointer;opacity:${count>0?1:0.6};" data-alert-target="${target}">
    <div style="font-size:1.5rem;">${icon}</div>
    <div style="font-size:1.3rem;font-weight:600;">${count}</div>
    <div style="font-size:0.75rem;color:#666;">${escapeHtml(labelText)}</div>
  </div>`;
}

function renderPipelineAlerts() {
  const alerts = [];
  (state.pipelineAggregate.alerts?.over_sla || []).forEach(a => alerts.push({type:'SLA', batch_id:a.batch_id, text:`${a.batch_id} — ${a.days_over}d sobre SLA`}));
  (state.pipelineAggregate.alerts?.no_activity_48h || []).forEach(a => alerts.push({type:'Inactivo', batch_id:a.batch_id, text:`${a.batch_id} — sin actividad 48h`}));
  (state.pipelineAggregate.alerts?.awaiting_reply || []).forEach(a => alerts.push({type:'Espera', batch_id:a.batch_id, text:`${a.batch_id} — esperando respuesta`}));
  if (alerts.length === 0) return '';
  return `<div style="margin-top:0.75rem;">
    <div style="font-size:0.8rem;font-weight:600;color:#888;margin-bottom:0.4rem;">Alertas</div>
    ${alerts.map(a => `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:0.4rem 0;border-bottom:1px solid #eee;font-size:0.85rem;">
        <span><span style="color:#e67e22;font-weight:500;">[${a.type}]</span> ${escapeHtml(a.text)}</span>
        <button type="button" class="btn btn-sm btn-secondary ov-open-batch" data-batch-id="${escapeHtml(a.batch_id)}">Abrir batch</button>
      </div>
    `).join('')}
  </div>`;
}

function renderPoMiniTable(pos) {
  return `<table style="width:100%;font-size:0.9rem;border-collapse:collapse;">
    <thead><tr style="text-align:left;border-bottom:1px solid #ddd;">
      <th>ID</th><th>Proveedor</th><th>Total</th><th>Estado</th><th>ETA</th>
    </tr></thead>
    <tbody>
      ${pos.map(p => `
        <tr style="border-bottom:1px solid #eee;cursor:pointer;" class="ov-po-row" data-po-id="${escapeHtml(p.id)}">
          <td><code>${escapeHtml(p.id)}</code></td>
          <td>${escapeHtml(p.supplier_name || p.supplier_id)}</td>
          <td>${formatCurrency(p.total_cost || p.total_amount, p.currency)}</td>
          <td><span style="background:${PO_STATUS_COLORS[p.status]||'#6c757d'};color:#fff;padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;">${window.label(`po_status.${p.status}`)||p.status}</span></td>
          <td>${formatDate(p.expected_delivery_at)}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
}

async function loadDashboardData() {
  try {
    const [restock, suggested, pipeline, posData, suppliers, items] = await Promise.all([
      api('/restock-status').catch(() => ({ items: [] })),
      api('/suggested-actions').catch(() => ({ actions: [] })),
      api('/pipeline-aggregate').catch(() => ({ counts: {}, alerts: {} })),
      api('/pos?limit=5').catch(() => ({ pos: [] })),
      api('/suppliers?limit=200').catch(() => ({ suppliers: [] })),
      api('/items?limit=200').catch(() => ({ items: [] }))
    ]);
    state.restockStatus = restock.items || [];
    state.suggestedActions = suggested.actions || [];
    state.pipelineAggregate = pipeline;
    state.pos = posData.pos || [];
    state.suppliers = suppliers.suppliers || [];
    state.items = items.items || [];
    state.groupedRestock = [];
  } catch (err) {
    console.error('Error cargando dashboard:', err);
    window.toast('Error cargando overview', 'error');
  }
}

function buildGroupedRestockFromItems(items) {
  const groups = {};
  items.forEach(it => {
    const sid = it.supplier_id || it.supplierId || 'unknown';
    const sname = it.supplier_name || it.supplierName || null;
    if (!groups[sid]) {
      groups[sid] = { supplier_id: sid, supplier_name: sname, items: [] };
    }
    groups[sid].items.push(it);
  });
  Object.values(groups).forEach(g => {
    if (!g.supplier_name || g.supplier_name === 'unknown') {
      const s = state.suppliers.find(sup => sup.id === g.supplier_id);
      if (s) g.supplier_name = s.name;
    }
  });
  return Object.values(groups);
}

function initDashboardEvents(root) {
  root.querySelector('#ov-btn-all-pos')?.addEventListener('click', () => {
    state.currentView = 'pos_list';
    refreshOverview(root);
  });
  root.querySelector('#ov-btn-new-po')?.addEventListener('click', () => {
    state.currentView = 'po_create';
    refreshOverview(root);
  });
  root.querySelector('#ov-btn-grouped-restock')?.addEventListener('click', async () => {
    try {
      const data = await api('/restock-status/grouped-by-supplier');
      state.groupedRestock = data.groups || data.suppliers || [];
      if (state.groupedRestock.length === 0 && state.restockStatus.length > 0) {
        const urgent = state.restockStatus.filter(r => ['out_of_stock','order_now'].includes(r.urgency_level));
        state.groupedRestock = buildGroupedRestockFromItems(urgent);
      }
      openGroupedRestockModal(root);
    } catch (err) {
      const urgent = state.restockStatus.filter(r => ['out_of_stock','order_now'].includes(r.urgency_level));
      state.groupedRestock = buildGroupedRestockFromItems(urgent);
      if (state.groupedRestock.length > 0) {
        openGroupedRestockModal(root);
      } else {
        window.toast(err.message, 'error');
      }
    }
  });
  root.querySelectorAll('.ov-po-row').forEach(row => {
    row.addEventListener('click', () => {
      state.currentView = 'po_detail';
      state.selectedPoId = row.dataset.poId;
      refreshOverview(root);
    });
  });
  root.querySelectorAll('.ov-open-batch').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      window.location.hash = `#/stock/batches?open=${encodeURIComponent(btn.dataset.batchId)}`;
    });
  });
  root.querySelectorAll('[data-alert-target]').forEach(card => {
    card.addEventListener('click', () => {
      const target = card.dataset.alertTarget;
      if (target === 'pos') { state.currentView = 'pos_list'; refreshOverview(root); }
      else if (target === 'batches') { window.location.hash = '#/stock/batches'; }
    });
  });
  root.querySelectorAll('.ov-suggested-link').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const link = btn.dataset.link;
      if (link) window.location.hash = link;
    });
  });
}

/* ═══════════════════════════════════════════════════
   BLOQUE B — PO LIST
   ═══════════════════════════════════════════════════ */

function renderPoList() {
  let filtered = state.pos;
  if (state.poFilterStatus !== 'all') {
    filtered = filtered.filter(p => p.status === state.poFilterStatus);
  }
  if (state.poSupplierFilter) {
    filtered = filtered.filter(p => p.supplier_id === state.poSupplierFilter);
  }
  if (state.poSearch) {
    const q = state.poSearch.toLowerCase();
    filtered = filtered.filter(p =>
      (p.id || '').toLowerCase().includes(q) ||
      (p.notes || '').toLowerCase().includes(q) ||
      (p.supplier_name || p.supplier_id || '').toLowerCase().includes(q)
    );
  }

  return `
    <div id="overview-po-list">
      <div style="margin-bottom:1rem;">
        <button type="button" class="btn btn-secondary" id="po-btn-back-dash">&larr; Volver al dashboard</button>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.75rem;margin-bottom:1rem;">
        <h3 style="margin:0;">Pedidos</h3>
        <button type="button" class="btn btn-primary" id="po-btn-new-from-list">Nuevo pedido</button>
      </div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem;align-items:center;">
        ${PO_STATUSES.map(s => {
          const active = state.poFilterStatus === s;
          const count = state.pos.filter(p => p.status === s).length;
          return `<button type="button" class="filter-pill${active ? ' active' : ''}" data-po-status="${s}" style="padding:0.25rem 0.6rem;border-radius:12px;border:1px solid ${active?PO_STATUS_COLORS[s]:'#ddd'};background:${active?PO_STATUS_COLORS[s]:'#fff'};color:${active?'#fff':'#666'};cursor:pointer;font-size:0.8rem;">${window.label(`po_status.${s}`)||s} (${count})</button>`;
        }).join('')}
        <button type="button" class="filter-pill${state.poFilterStatus==='all'?' active':''}" data-po-status="all" style="padding:0.25rem 0.6rem;border-radius:12px;border:1px solid ${state.poFilterStatus==='all'?'#6c757d':'#ddd'};background:${state.poFilterStatus==='all'?'#6c757d':'#fff'};color:${state.poFilterStatus==='all'?'#fff':'#666'};cursor:pointer;font-size:0.8rem;">Todos (${state.pos.length})</button>
      </div>
      <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;">
        <input type="text" id="po-search-input" placeholder="Buscar ID, notas, proveedor..." value="${escapeHtml(state.poSearch)}" style="padding:0.4rem 0.6rem;border:1px solid #ddd;border-radius:4px;min-width:220px;font-size:0.9rem;">
        <select id="po-supplier-filter" style="padding:0.4rem 0.6rem;border:1px solid #ddd;border-radius:4px;font-size:0.9rem;">
          <option value="">Todos los proveedores</option>
          ${state.suppliers.map(s => `<option value="${escapeHtml(s.id)}" ${state.poSupplierFilter===s.id?'selected':''}>${escapeHtml(s.name)}</option>`).join('')}
        </select>
      </div>
      ${filtered.length === 0 ? `<div style="color:#888;">Sin pedidos.</div>` : renderPoTable(filtered)}
    </div>
  `;
}

function renderPoTable(pos) {
  return `<table style="width:100%;font-size:0.9rem;border-collapse:collapse;">
    <thead><tr style="text-align:left;border-bottom:1px solid #ddd;">
      <th>ID</th><th>Estado</th><th>Proveedor</th><th>Total</th><th>ETA</th><th>Líneas</th>
    </tr></thead>
    <tbody>
      ${pos.map(p => `
        <tr style="border-bottom:1px solid #eee;cursor:pointer;" class="po-table-row" data-po-id="${escapeHtml(p.id)}">
          <td><code>${escapeHtml(p.id)}</code></td>
          <td><span style="background:${PO_STATUS_COLORS[p.status]||'#6c757d'};color:#fff;padding:0.15rem 0.4rem;border-radius:4px;font-size:0.75rem;">${window.label(`po_status.${p.status}`)||p.status}</span></td>
          <td>${escapeHtml(p.supplier_name || p.supplier_id)}</td>
          <td>${formatCurrency(p.total_cost || p.total_amount, p.currency)}</td>
          <td>${formatDate(p.expected_delivery_at)}</td>
          <td>${p.items?.length || 0}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>`;
}

function initPoListEvents(root) {
  root.querySelector('#po-btn-back-dash')?.addEventListener('click', () => {
    state.currentView = 'dashboard';
    refreshOverview(root);
  });
  root.querySelector('#po-btn-new-from-list')?.addEventListener('click', () => {
    state.currentView = 'po_create';
    refreshOverview(root);
  });
  root.querySelectorAll('[data-po-status]').forEach(btn => {
    btn.addEventListener('click', () => {
      state.poFilterStatus = btn.dataset.poStatus;
      refreshOverview(root);
    });
  });
  root.querySelector('#po-search-input')?.addEventListener('input', (e) => {
    state.poSearch = e.target.value;
    refreshOverview(root);
  });
  root.querySelector('#po-supplier-filter')?.addEventListener('change', (e) => {
    state.poSupplierFilter = e.target.value;
    refreshOverview(root);
  });
  root.querySelectorAll('.po-table-row').forEach(row => {
    row.addEventListener('click', () => {
      state.currentView = 'po_detail';
      state.selectedPoId = row.dataset.poId;
      refreshOverview(root);
    });
  });
}

/* ═══════════════════════════════════════════════════
   BLOQUE B — PO DETAIL
   ═══════════════════════════════════════════════════ */

function renderPoDetail() {
  const po = state.pos.find(p => p.id === state.selectedPoId);
  if (!po) return '<div>Pedido no encontrado.</div>';

  const supplier = state.suppliers.find(s => s.id === po.supplier_id) || {};
  const statusActions = getPoStatusActions(po.status);
  const poItems = po.items || [];

  return `
    <div id="overview-po-detail">
      <div style="margin-bottom:1rem;">
        <button type="button" class="btn btn-secondary" id="po-detail-btn-back">&larr; Volver a pedidos</button>
      </div>
      <div class="card" style="padding:1.5rem;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:1rem;">
          <div>
            <code style="font-size:1.1rem;">${escapeHtml(po.id)}</code>
            <span style="background:${PO_STATUS_COLORS[po.status]||'#6c757d'};color:#fff;padding:0.2rem 0.6rem;border-radius:4px;font-size:0.8rem;margin-left:0.5rem;">${window.label(`po_status.${po.status}`)||po.status}</span>
          </div>
          <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
            ${statusActions.map(a => `<button type="button" class="btn ${a.primary?'btn-primary':'btn-secondary'}" data-po-action="${a.action}">${a.label}</button>`).join('')}
          </div>
        </div>

        <div style="margin-top:1.2rem;">
          <h4 style="margin-bottom:0.5rem;">${escapeHtml(supplier.name || po.supplier_id)}</h4>
          <div style="color:#666;">${formatCurrency(po.total_cost || po.total_amount, po.currency)} &middot; Creado ${timeAgo(po.created_at)}</div>
        </div>

        <div style="margin-top:1.5rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1.5rem;">
          <div>
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Información</h5>
            <div style="font-size:0.9rem;line-height:1.6;">
              <div><strong>Fecha pedido:</strong> ${formatDate(po.created_at)}</div>
              <div><strong>ETA:</strong> ${formatDate(po.expected_delivery_at)}</div>
              <div><strong>Llegada real:</strong> ${formatDate(po.received_at)}</div>
              <div><strong>Moneda:</strong> ${po.currency}</div>
              ${po.notes ? `<div style="margin-top:0.5rem;color:#666;font-style:italic;">${escapeHtml(po.notes)}</div>` : ''}
            </div>
          </div>
        </div>

        <div style="margin-top:1.5rem;">
          <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Líneas del pedido</h5>
          <table style="width:100%;font-size:0.9rem;border-collapse:collapse;">
            <thead><tr style="text-align:left;border-bottom:1px solid #ddd;">
              <th>SKU</th><th>Item</th><th>Cantidad</th><th>Precio unit.</th><th>Subtotal</th><th>Notas</th>
            </tr></thead>
            <tbody>
              ${poItems.map(l => {
                const item = state.items.find(i => i.sku === l.item_sku) || {};
                const qty = l.quantity_ordered || l.quantity || 0;
                const cost = l.unit_cost || l.unit_price || 0;
                return `<tr style="border-bottom:1px solid #eee;">
                  <td><code>${escapeHtml(l.item_sku)}</code></td>
                  <td>${escapeHtml(l.item_name || item.name || '—')}</td>
                  <td>${qty}</td>
                  <td>${formatCurrency(cost, po.currency)}</td>
                  <td>${formatCurrency(qty * cost, po.currency)}</td>
                  <td>${escapeHtml(l.notes || '')}</td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>

        ${po.linked_batch_ids?.length > 0 ? `
          <div style="margin-top:1.5rem;">
            <h5 style="font-size:0.85rem;text-transform:uppercase;color:#888;margin-bottom:0.4rem;">Lotes vinculados</h5>
            <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
              ${po.linked_batch_ids.map(bid => `
                <a href="#/stock/batches?open=${encodeURIComponent(bid)}" class="btn btn-sm btn-secondary">${escapeHtml(bid)}</a>
              `).join('')}
            </div>
          </div>
        ` : ''}
      </div>
    </div>
  `;
}

function getPoStatusActions(status) {
  const actions = [];
  if (status === 'draft') {
    actions.push({ action: 'edit', label: window.label('po_actions.edit'), primary: false });
    actions.push({ action: 'send', label: window.label('po_actions.mark_sent'), primary: true });
    actions.push({ action: 'cancel', label: window.label('po_actions.cancel'), primary: false });
  } else if (status === 'sent') {
    actions.push({ action: 'confirm', label: window.label('po_actions.mark_confirmed'), primary: false });
    actions.push({ action: 'ship', label: window.label('po_actions.mark_shipped'), primary: true });
    actions.push({ action: 'cancel', label: window.label('po_actions.cancel'), primary: false });
  } else if (status === 'confirmed') {
    actions.push({ action: 'ship', label: window.label('po_actions.mark_shipped'), primary: true });
    actions.push({ action: 'cancel', label: window.label('po_actions.cancel'), primary: false });
  } else if (status === 'shipped') {
    actions.push({ action: 'receive', label: window.label('po_actions.receive'), primary: true });
    actions.push({ action: 'cancel', label: window.label('po_actions.cancel'), primary: false });
  }
  return actions;
}

function initPoDetailEvents(root) {
  root.querySelector('#po-detail-btn-back')?.addEventListener('click', () => {
    state.currentView = 'pos_list';
    refreshOverview(root);
  });
  root.querySelectorAll('[data-po-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.poAction;
      const po = state.pos.find(p => p.id === state.selectedPoId);
      if (!po) return;
      await handlePoAction(root, po, action);
    });
  });
}

async function handlePoAction(root, po, action) {
  try {
    if (action === 'cancel') {
      if (!await window.confirmModal('¿Cancelar pedido?', 'Esta acción no se puede deshacer.', 'Cancelar', true)) return;
      await api(`/pos/${encodeURIComponent(po.id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'cancelled' }) });
      window.toast('Pedido cancelado.');
    } else if (action === 'send') {
      await api(`/pos/${encodeURIComponent(po.id)}/transition`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to_status: 'sent' }) });
      window.toast('Pedido enviado.');
    } else if (action === 'confirm') {
      await api(`/pos/${encodeURIComponent(po.id)}/transition`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to_status: 'confirmed' }) });
      window.toast('Pedido confirmado.');
    } else if (action === 'ship') {
      await api(`/pos/${encodeURIComponent(po.id)}/transition`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ to_status: 'shipped' }) });
      window.toast('Pedido en tránsito.');
    } else if (action === 'receive') {
      openReceiveModal(root, po);
      return;
    } else if (action === 'edit') {
      state.currentView = 'po_create';
      state._editingPo = po;
      refreshOverview(root);
      return;
    }
    await reloadPoData();
    refreshOverview(root);
  } catch (err) {
    window.toast(err.message, 'error');
  }
}

/* ═══════════════════════════════════════════════════
   BLOQUE B — PO CREATE
   ═══════════════════════════════════════════════════ */

function renderPoCreate() {
  const editing = state._editingPo || null;
  const prefillSupplier = state._prefillSupplier || '';
  const prefillItems = state._prefillItems || null;
  const po = editing || { supplier_id: prefillSupplier, expected_delivery_at: '', notes: '', items: prefillItems || [{ item_sku: '', quantity: 1, unit_price: 0, notes: '' }] };

  return `
    <div id="overview-po-create">
      <div style="margin-bottom:1rem;">
        <button type="button" class="btn btn-secondary" id="po-create-btn-back">&larr; Volver</button>
      </div>
      <div class="card" style="padding:1.5rem;">
        <h3 style="margin-top:0;">${editing ? 'Editar pedido' : 'Nuevo pedido'}</h3>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem;margin-bottom:1rem;">
          <div>
            <label style="display:block;font-size:0.8rem;color:#888;margin-bottom:0.3rem;">Proveedor *</label>
            <select id="po-create-supplier" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
              <option value="">Seleccionar...</option>
              ${state.suppliers.filter(s => s.active !== false).map(s => `
                <option value="${escapeHtml(s.id)}" ${po.supplier_id===s.id?'selected':''}>${escapeHtml(s.name)}</option>
              `).join('')}
            </select>
          </div>
          <div>
            <label style="display:block;font-size:0.8rem;color:#888;margin-bottom:0.3rem;">Fecha esperada entrega</label>
            <input type="date" id="po-create-eta" value="${po.expected_delivery_at ? po.expected_delivery_at.slice(0,10) : ''}" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
          </div>
        </div>
        <div style="margin-bottom:1rem;">
          <label style="display:block;font-size:0.8rem;color:#888;margin-bottom:0.3rem;">Notas</label>
          <textarea id="po-create-notes" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;">${escapeHtml(po.notes || '')}</textarea>
        </div>

        <h4 style="font-size:1rem;margin:1rem 0 0.5rem;">Líneas</h4>
        <div id="po-lines-container">
          ${(po.items || []).map((l, idx) => renderPoLineRow(l, idx, po.items.length)).join('')}
        </div>
        <button type="button" class="btn btn-secondary" id="po-add-line" style="margin-top:0.5rem;">+ Añadir línea</button>

        <div style="margin-top:1rem;text-align:right;font-weight:600;" id="po-create-total">
          Total: ${formatCurrency(calculatePoTotal(po.items), 'EUR')}
        </div>

        <div style="display:flex;gap:0.5rem;justify-content:flex-end;margin-top:1.5rem;">
          <button type="button" class="btn btn-secondary" id="po-save-draft">${window.label('po_actions.save_draft')}</button>
          <button type="button" class="btn btn-primary" id="po-save-send">${window.label('po_actions.save_and_send')}</button>
        </div>
      </div>
    </div>
  `;
}

function renderPoLineRow(line, idx, totalLines) {
  return `
    <div class="po-line-row" data-line-idx="${idx}" style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr 2fr auto;gap:0.5rem;align-items:end;margin-bottom:0.5rem;">
      <div>
        <label style="font-size:0.75rem;color:#888;">SKU *</label>
        <select class="po-line-sku" style="width:100%;padding:0.35rem;border:1px solid #ddd;border-radius:4px;">
          <option value="">Seleccionar...</option>
          ${state.items.filter(i => i.active !== false).map(i => `
            <option value="${escapeHtml(i.sku)}" ${line.item_sku===i.sku?'selected':''}>${escapeHtml(i.sku)} — ${escapeHtml(i.name)}</option>
          `).join('')}
        </select>
      </div>
      <div>
        <label style="font-size:0.75rem;color:#888;">Cantidad *</label>
        <input type="number" class="po-line-qty" min="1" value="${line.quantity}" style="width:100%;padding:0.35rem;border:1px solid #ddd;border-radius:4px;">
      </div>
      <div>
        <label style="font-size:0.75rem;color:#888;">Precio unit.</label>
        <input type="number" class="po-line-price" min="0" step="0.01" value="${line.unit_price}" style="width:100%;padding:0.35rem;border:1px solid #ddd;border-radius:4px;">
      </div>
      <div>
        <label style="font-size:0.75rem;color:#888;">Subtotal</label>
        <div class="po-line-subtotal" style="padding:0.35rem;font-size:0.9rem;">${formatCurrency(line.quantity * line.unit_price, 'EUR')}</div>
      </div>
      <div>
        <label style="font-size:0.75rem;color:#888;">Notas línea</label>
        <input type="text" class="po-line-notes" value="${escapeHtml(line.notes || '')}" style="width:100%;padding:0.35rem;border:1px solid #ddd;border-radius:4px;">
      </div>
      ${totalLines > 1 ? `<button type="button" class="btn btn-sm btn-danger po-line-delete" style="padding:0.35rem 0.5rem;">🗑</button>` : ''}
    </div>
  `;
}

function initPoCreateEvents(root) {
  root.querySelector('#po-create-btn-back')?.addEventListener('click', () => {
    state.currentView = 'pos_list';
    state._editingPo = null;
    state._prefillSupplier = null;
    state._prefillItems = null;
    refreshOverview(root);
  });

  const linesContainer = root.querySelector('#po-lines-container');
  linesContainer?.addEventListener('change', updatePoTotals);
  linesContainer?.addEventListener('input', updatePoTotals);

  root.querySelector('#po-add-line')?.addEventListener('click', () => {
    const rows = linesContainer.querySelectorAll('.po-line-row');
    const newIdx = rows.length;
    const div = document.createElement('div');
    div.innerHTML = renderPoLineRow({ item_sku: '', quantity: 1, unit_price: 0, notes: '' }, newIdx, newIdx + 1);
    linesContainer.appendChild(div.firstElementChild);
    updatePoTotals();
  });

  linesContainer?.addEventListener('click', (e) => {
    if (e.target.closest('.po-line-delete')) {
      e.target.closest('.po-line-row').remove();
      updatePoTotals();
    }
  });

  root.querySelector('#po-save-draft')?.addEventListener('click', () => submitPoCreate(root, 'draft'));
  root.querySelector('#po-save-send')?.addEventListener('click', () => submitPoCreate(root, 'sent'));
}

function updatePoTotals() {
  const rows = document.querySelectorAll('.po-line-row');
  let total = 0;
  rows.forEach(row => {
    const qty = Number(row.querySelector('.po-line-qty')?.value) || 0;
    const price = Number(row.querySelector('.po-line-price')?.value) || 0;
    const sub = qty * price;
    row.querySelector('.po-line-subtotal').textContent = formatCurrency(sub, 'EUR');
    total += sub;
  });
  const totalEl = document.getElementById('po-create-total');
  if (totalEl) totalEl.textContent = `Total: ${formatCurrency(total, 'EUR')}`;
}

function calculatePoTotal(items) {
  return (items || []).reduce((sum, l) => sum + (l.quantity * l.unit_price), 0);
}

// FIX v1.4: traducir quantity -> quantity_ordered, unit_price -> unit_cost para el backend
function collectPoItems() {
  const rows = document.querySelectorAll('.po-line-row');
  const items = [];
  rows.forEach((row, idx) => {
    const sku = row.querySelector('.po-line-sku')?.value?.trim();
    const qtyRaw = row.querySelector('.po-line-qty')?.value;
    const priceRaw = row.querySelector('.po-line-price')?.value;
    const qty = Math.floor(parseInt(qtyRaw, 10)) || 0;
    const price = parseFloat(priceRaw) || 0;
    const notes = row.querySelector('.po-line-notes')?.value || '';
    if (sku && qty > 0) {
      const item = state.items.find(i => i.sku === sku);
      items.push({
        item_sku: sku,
        item_name: item?.name || sku,
        quantity_ordered: qty,
        unit_cost: price,
        notes
      });
    }
  });
  return items;
}

async function submitPoCreate(root, targetStatus) {
  const supplierId = root.querySelector('#po-create-supplier')?.value;
  const eta = root.querySelector('#po-create-eta')?.value;
  const notes = root.querySelector('#po-create-notes')?.value;
  const items = collectPoItems();

  if (!supplierId) { window.toast('Selecciona un proveedor.', 'error'); return; }
  if (items.length === 0) { window.toast('Añade al menos una línea.', 'error'); return; }

  const body = {
    supplier_id: supplierId,
    expected_delivery_at: eta || null,
    notes,
    items,
    status: targetStatus,
    currency: 'EUR'
  };

  console.log('[PO Create] ===== BODY ENVIADO =====');
  console.log(JSON.stringify(body, null, 2));
  console.log('[PO Create] ========================');

  try {
    const editing = state._editingPo;
    let res;
    if (editing) {
      res = await api(`/pos/${encodeURIComponent(editing.id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      window.toast('Pedido actualizado.');
    } else {
      res = await api('/pos', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      window.toast(targetStatus === 'sent' ? 'Pedido creado y enviado.' : 'Pedido guardado como borrador.');
    }
    console.log('[PO Create] Respuesta OK:', res);
    state._editingPo = null;
    state._prefillSupplier = null;
    state._prefillItems = null;
    state.currentView = 'pos_list';
    await reloadPoData();
    refreshOverview(root);
  } catch (err) {
    console.error('[PO Create] ERROR:', err);
    window.toast(err.message, 'error');
  }
}

/* ═══════════════════════════════════════════════════
   MODALES AUXILIARES
   ═══════════════════════════════════════════════════ */

function openReceiveModal(root, po) {
  const poItems = po.items || [];
  const linesHtml = poItems.map((l, idx) => `
    <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:0.5rem;margin-bottom:0.5rem;align-items:center;">
      <div><code>${escapeHtml(l.item_sku)}</code> ${escapeHtml(l.item_name || '')}</div>
      <div style="text-align:center;">Pedido: <strong>${l.quantity_ordered || l.quantity || 0}</strong></div>
      <div><input type="number" class="receive-qty" data-idx="${idx}" min="0" max="${l.quantity_ordered || l.quantity || 0}" value="${l.quantity_ordered || l.quantity || 0}" style="width:100%;padding:0.35rem;border:1px solid #ddd;border-radius:4px;"></div>
    </div>
  `).join('');

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width:600px;">
      <p class="modal-title">${window.label('po_receive_modal.title')} ${escapeHtml(po.id)}</p>
      <p class="modal-message" style="font-size:0.9rem;color:#666;">${window.label('po_receive_modal.info')}</p>
      <div style="margin:1rem 0;">${linesHtml}</div>
      <div style="margin-bottom:1rem;">
        <label style="display:block;font-size:0.8rem;color:#888;margin-bottom:0.3rem;">${window.label('po_receive_modal.delivery_date_label')}</label>
        <input type="date" id="receive-date" value="${new Date().toISOString().slice(0,10)}" style="padding:0.4rem;border:1px solid #ddd;border-radius:4px;">
      </div>
      <div style="margin-bottom:1rem;">
        <label style="display:block;font-size:0.8rem;color:#888;margin-bottom:0.3rem;">Notas</label>
        <textarea id="receive-notes" rows="2" style="width:100%;padding:0.4rem;border:1px solid #ddd;border-radius:4px;"></textarea>
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cancelar</button>
        <button type="button" class="btn btn-primary" data-action="confirm">Confirmar recepción</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.querySelector('[data-action="confirm"]').addEventListener('click', async () => {
    const receivedItems = poItems.map((l, idx) => {
      const input = overlay.querySelector(`.receive-qty[data-idx="${idx}"]`);
      return { item_sku: l.item_sku, quantity_received: Number(input?.value) || 0, notes: l.notes };
    });
    const date = overlay.querySelector('#receive-date')?.value;
    const notes = overlay.querySelector('#receive-notes')?.value;
    try {
      const res = await api(`/pos/${encodeURIComponent(po.id)}/receive`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ items: receivedItems, actual_delivery_at: date || null, notes })
      });
      window.toast(`Pedido recibido. ${res.batches_created?.length || 0} lotes creados.`);
      overlay.remove();
      await reloadPoData();
      refreshOverview(root);
    } catch (err) {
      window.toast(err.message, 'error');
    }
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

function openGroupedRestockModal(root) {
  const groups = state.groupedRestock;
  if (groups.length === 0) { window.toast('No hay items urgentes agrupados.', 'error'); return; }

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width:700px;">
      <p class="modal-title">Crear pedidos agrupados por proveedor</p>
      <p style="font-size:0.85rem;color:#888;margin:-0.5rem 0 1rem;">Ajusta las cantidades y selecciona un proveedor para crear el PO.</p>
      <div style="max-height:60vh;overflow:auto;">
        ${groups.map((g, gIdx) => `
          <div style="margin-bottom:1.5rem;padding:1rem;background:#f8f9fa;border-radius:6px;" data-group-idx="${gIdx}">
            <div style="font-weight:600;margin-bottom:0.5rem;font-size:1rem;">${escapeHtml(g.supplier_name || g.supplier_id || 'Proveedor desconocido')}</div>
            <table style="width:100%;font-size:0.85rem;border-collapse:collapse;">
              <thead><tr style="border-bottom:1px solid #ddd;">
                <th>SKU</th><th style="width:100px;">Cantidad</th><th>Urgencia</th>
              </tr></thead>
              <tbody>
                ${g.items.map((it, iIdx) => `
                  <tr style="border-bottom:1px solid #eee;" data-item-idx="${iIdx}">
                    <td><code>${escapeHtml(it.item_sku)}</code></td>
                    <td><input type="number" class="grouped-qty" min="1" value="${it.suggested_quantity || it.quantity || 1}" style="width:80px;padding:0.25rem;border:1px solid #ddd;border-radius:4px;"></td>
                    <td><span style="background:${URGENCY_COLORS[it.urgency_level]||'#6c757d'};color:#fff;padding:0.1rem 0.4rem;border-radius:3px;font-size:0.7rem;">${window.label(`urgency.${it.urgency_level}`)||it.urgency_level}</span></td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
            <button type="button" class="btn btn-primary btn-sm grouped-po-create" data-group-idx="${gIdx}" style="margin-top:0.75rem;">Crear PO con estos items</button>
          </div>
        `).join('')}
      </div>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cerrar</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelectorAll('.grouped-po-create').forEach(btn => {
    btn.addEventListener('click', () => {
      const gIdx = parseInt(btn.dataset.groupIdx, 10);
      const group = groups[gIdx];
      if (!group) return;

      const groupEl = overlay.querySelector(`[data-group-idx="${gIdx}"]`);
      const qtyInputs = groupEl.querySelectorAll('.grouped-qty');
      const prefillItems = group.items.map((it, iIdx) => {
        const input = qtyInputs[iIdx];
        const qty = Math.floor(parseInt(input?.value, 10)) || 1;
        return {
          item_sku: it.item_sku,
          quantity: qty,
          unit_price: 0,
          notes: `Auto-sugerido: ${window.label(`urgency.${it.urgency_level}`)||it.urgency_level}`
        };
      });

      state._editingPo = null;
      state._prefillItems = prefillItems;
      state._prefillSupplier = group.supplier_id;
      state.currentView = 'po_create';
      overlay.remove();
      refreshOverview(root);
    });
  });
  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
}

/* ═══════════════════════════════════════════════════
   REFRESH + DATA
   ═══════════════════════════════════════════════════ */

async function reloadPoData() {
  try {
    const data = await api('/pos?limit=50');
    state.pos = data.pos || [];
  } catch (err) {
    console.error('Error recargando POs:', err);
  }
}

function refreshOverview(root) {
  root.innerHTML = renderOverviewView();
  initOverview(root);
}
