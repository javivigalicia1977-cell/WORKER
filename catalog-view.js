// catalog-view.js — v1.0 (C.5-B.3) — Catálogo: Items + BOM
// Backend: v6.12.5-stock-no-totp

import { LABELS, label } from '/js/stock-labels.js?v=2';
import { toast, confirmModal } from '/js/ui.js?v=2';

/* ═══════════════════════════════════════════════════════════════════
   MODULE STATE
   ═══════════════════════════════════════════════════════════════════ */

let state = {
  view: 'list',
  selectedId: null,
  items: [],
  suppliers: [],
  categories: [],
  filtered: [],
  filterCategory: 'all',
  filterLowStock: false,
  searchQuery: '',
  isLoading: false
};

const ITEM_CATEGORIES = ['packaging', 'garment', 'raw_material', 'finished_good', 'hardware', 'label'];
const ORIGIN_TYPES = ['local', 'eu', 'extra_eu'];
const UNITS = ['units', 'meters', 'kilograms', 'liters'];

/* ── helpers ─────────────────────────────────────── */

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function api(path, options = {}) {
  const url = `/api/proxy/admin/stock${path}`;
  const res = await fetch(url, options);
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'unknown' }));
    throw new Error(data.detail || data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function getStatusChip(item) {
  const qty = item.current_stock || 0;
  const min = item.min_threshold || 0;
  const crit = item.critical_threshold || 0;
  let status = 'healthy';
  let color = 'var(--success)';
  if (qty === 0) { status = 'out_of_stock'; color = 'var(--danger)'; }
  else if (crit > 0 && qty <= crit) { status = 'critical'; color = '#e67e22'; }
  else if (min > 0 && qty <= min) { status = 'low'; color = '#f1c40f'; }
  const text = label(`item_status.${status}`) || status;
  return `<span class="tag" style="background:${color}15;color:${color};font-size:var(--size-xs);padding:2px 8px;">${text}</span>`;
}

function getCategoryChip(cat) {
  return `<span class="tag" style="background:var(--potisse-cream-dark);color:var(--potisse-chocolate);font-size:var(--size-xs);padding:2px 8px;">${escapeHtml(label(`item_category.${cat}`) || cat)}</span>`;
}

function getSupplierName(supplierId) {
  if (!supplierId) return '-';
  const s = state.suppliers.find(x => x.id === supplierId);
  return s ? s.name : supplierId;
}

/* ═══════════════════════════════════════════════════════════════════
   EXPORTS
   ═══════════════════════════════════════════════════════════════════ */

export function renderCatalogView() {
  if (state.view === 'list') return renderListView();
  if (state.view === 'detail') return renderDetailView();
  if (state.view === 'create' || state.view === 'edit') return renderFormView(state.selectedId);
  if (state.view === 'bom') return renderBomView();
  return renderListView();
}

export async function initCatalog(root) {
  if (state.view === 'list') initListEvents(root);
  else if (state.view === 'detail') initDetailEvents(root);
  else if (state.view === 'create' || state.view === 'edit') initFormEvents(root);
  else if (state.view === 'bom') initBomEvents(root);
  await loadItems(root);
  await loadSuppliers(root);
  await loadCategories(root);
}

/* ═══════════════════════════════════════════════════════════════════
   LIST VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderListView() {
  return `
    <div id="catalog-list-view">
      <div class="toolbar" style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-4);">
        <div class="toolbar-filters" style="display:flex;gap:var(--space-1);flex-wrap:wrap;">
          <button type="button" class="filter-pill${state.filterCategory === 'all' ? ' active' : ''}" data-filter="all">Todos</button>
          ${ITEM_CATEGORIES.map(c => `<button type="button" class="filter-pill${state.filterCategory === c ? ' active' : ''}" data-filter="${c}">${escapeHtml(label(`item_category.${c}`) || c)}</button>`).join('')}
          <button type="button" class="filter-pill${state.filterLowStock ? ' active' : ''}" data-filter="lowstock">Solo bajo stock</button>
        </div>
        <div style="flex:1;min-width:200px;">
          <input type="text" id="cat-search" placeholder="Buscar por nombre, SKU o ID..." value="${escapeHtml(state.searchQuery)}" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
        </div>
        <button type="button" class="btn btn-primary" id="cat-btn-create">${LABELS.create} artículo</button>
        <button type="button" class="btn btn-secondary" id="cat-btn-refresh">${LABELS.refresh}</button>
      </div>
      <div id="catalog-list-content">
        ${renderItemRows()}
      </div>
    </div>
  `;
}

function renderItemRows() {
  if (state.isLoading) return '<div style="text-align:center;padding:var(--space-8);">Cargando...</div>';
  applyFilters();
  const rows = state.filtered;
  if (!rows.length) {
    return `
      <div class="empty-state" style="text-align:center;padding:var(--space-8);">
        <div style="font-size:3em;opacity:0.3;margin-bottom:var(--space-3);">◯</div>
        <h3 style="margin:0;font-weight:500;color:var(--text);">${LABELS.empty_no_items}</h3>
        <button type="button" class="btn btn-primary" id="cat-btn-bootstrap" style="margin-top:var(--space-4);">Nuevo artículo</button>
      </div>
    `;
  }
  return rows.map(item => {
    const supplierName = getSupplierName(item.supplier_id);
    return `
      <div class="card" data-item-id="${escapeHtml(item.id)}" style="display:flex;align-items:flex-start;gap:var(--space-3);padding:var(--space-3);cursor:pointer;margin-bottom:var(--space-2);border:1px solid var(--border);">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;">
            <span style="font-family:var(--font-mono);font-size:var(--size-sm);color:var(--potisse-chocolate);font-weight:500;">${escapeHtml(item.sku)}</span>
            ${getCategoryChip(item.category)}
            ${getStatusChip(item)}
            ${item.has_bom ? '<span class="tag" style="background:var(--border);color:var(--text-muted);font-size:var(--size-xs);padding:2px 8px;">BOM</span>' : ''}
          </div>
          <div style="margin-top:var(--space-1);font-weight:500;font-size:var(--size-sm);color:var(--text);">${escapeHtml(item.name)}</div>
          <div style="margin-top:var(--space-1);font-size:var(--size-xs);color:var(--muted);">
            Stock: ${item.current_stock || 0} ${escapeHtml(label(`unit_of_measure.${item.unit}`) || item.unit || 'unidades')} · 
            Umbral: ${item.min_threshold || 0}/${item.critical_threshold || 0} · 
            ${escapeHtml(supplierName)}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function applyFilters() {
  let rows = [...state.items];
  if (state.filterCategory !== 'all') {
    rows = rows.filter(i => i.category === state.filterCategory);
  }
  if (state.filterLowStock) {
    rows = rows.filter(i => {
      const qty = i.current_stock || 0;
      const min = i.min_threshold || 0;
      return qty <= min && min > 0;
    });
  }
  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase();
    rows = rows.filter(i =>
      (i.name || '').toLowerCase().includes(q) ||
      (i.sku || '').toLowerCase().includes(q) ||
      (i.id || '').toLowerCase().includes(q)
    );
  }
  state.filtered = rows;
}

/* ═══════════════════════════════════════════════════════════════════
   DETAIL VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderDetailView() {
  const item = state.items.find(x => x.id === state.selectedId);
  if (!item) return '<div style="padding:var(--space-4);">Artículo no encontrado.</div>';
  const supplierName = getSupplierName(item.supplier_id);
  return `
    <div id="catalog-detail-view">
      <button type="button" class="btn btn-secondary" id="cat-btn-back" style="margin-bottom:var(--space-2);">← Volver al catálogo</button>

      <div style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;margin-bottom:var(--space-3);">
        <span style="font-family:var(--font-mono);font-size:var(--size-lg);color:var(--potisse-chocolate);font-weight:500;">${escapeHtml(item.sku)}</span>
        ${getCategoryChip(item.category)}
        ${getStatusChip(item)}
        ${item.active !== false ? '' : '<span class="tag" style="background:var(--danger)15;color:var(--danger);font-size:var(--size-xs);padding:2px 8px;">Inactivo</span>'}
      </div>
      <h2 style="margin:0 0 var(--space-3) 0;font-weight:500;">${escapeHtml(item.name)}</h2>

      <div style="display:flex;gap:var(--space-2);margin-bottom:var(--space-4);">
        <button type="button" class="btn btn-primary" id="cat-btn-edit">${LABELS.edit}</button>
        <button type="button" class="btn btn-secondary" id="cat-btn-bom">BOM</button>
        <button type="button" class="btn btn-danger" id="cat-btn-delete">${LABELS.delete}</button>
      </div>

      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--space-3);">
        <div class="member-block" style="padding:var(--space-3);border:1px solid var(--border);">
          <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Información básica</h4>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-2);font-size:var(--size-sm);">
            <div><span style="color:var(--muted);font-size:var(--size-xs);">ID</span><div style="font-family:var(--font-mono);">${escapeHtml(item.id)}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">SKU</span><div>${escapeHtml(item.sku)}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Categoría</span><div>${escapeHtml(label(`item_category.${item.category}`) || item.category)}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Unidad</span><div>${escapeHtml(label(`unit_of_measure.${item.unit}`) || item.unit || 'unidades')}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Origen</span><div>${escapeHtml(label(`origin_type.${item.origin_type}`) || item.origin_type)}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Shopify</span><div>${item.is_shopify_master ? 'Master · ' + escapeHtml(item.shopify_variant_id || '-') : 'No'}</div></div>
          </div>
        </div>

        <div class="member-block" style="padding:var(--space-3);border:1px solid var(--border);">
          <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Stock y umbrales</h4>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-2);font-size:var(--size-sm);">
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Stock actual</span><div style="font-size:var(--size-lg);font-weight:500;">${item.current_stock || 0}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Umbral mínimo</span><div>${item.min_threshold || 0}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Umbral crítico</span><div>${item.critical_threshold || 0}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Estado</span><div>${getStatusChip(item)}</div></div>
          </div>
        </div>

        <div class="member-block" style="padding:var(--space-3);border:1px solid var(--border);">
          <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Proveedor y logística</h4>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-2);font-size:var(--size-sm);">
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Proveedor habitual</span><div>${escapeHtml(supplierName)}</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Plazo entrega</span><div>${item.standard_lead_time_days || 7} días</div></div>
            <div><span style="color:var(--muted);font-size:var(--size-xs);">Margen</span><div>${item.buffer_days != null ? item.buffer_days : 'auto'} días</div></div>
          </div>
        </div>
      </div>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   FORM VIEW (CREATE / EDIT)
   ═══════════════════════════════════════════════════════════════════ */

function renderFormView(editId = null) {
  const isEdit = !!editId;
  const item = isEdit ? state.items.find(x => x.id === editId) : null;
  const title = isEdit ? `Editar ${LABELS.item}` : `Crear ${LABELS.item}`;

  const values = {
    id: item?.id || '',
    sku: item?.sku || '',
    name: item?.name || '',
    category: item?.category || '',
    unit: item?.unit || 'units',
    min_threshold: item?.min_threshold != null ? item.min_threshold : '',
    critical_threshold: item?.critical_threshold != null ? item.critical_threshold : '',
    supplier_id: item?.supplier_id || '',
    standard_lead_time_days: item?.standard_lead_time_days != null ? item.standard_lead_time_days : 7,
    buffer_days: item?.buffer_days != null ? item.buffer_days : '',
    origin_type: item?.origin_type || 'local',
    is_shopify_master: item?.is_shopify_master || false,
    shopify_variant_id: item?.shopify_variant_id || '',
    active: item?.active !== false
  };

  const idReadonly = isEdit ? 'readonly style="background:var(--border);"' : '';
  const idTooltip = isEdit ? 'title="ID interno immutable"' : '';
  const shopifyDisabled = values.is_shopify_master ? '' : 'disabled style="background:var(--border);"';

  const supplierOptions = state.suppliers.filter(s => s.active !== false).map(s => 
    `<option value="${escapeHtml(s.id)}" ${values.supplier_id === s.id ? 'selected' : ''}>${escapeHtml(s.name)}</option>`
  ).join('');

  return `
    <div id="catalog-form-view">
      <button type="button" class="btn btn-secondary" id="cat-btn-back-form" style="margin-bottom:var(--space-2);">← Volver</button>
      <h2 style="margin:0 0 var(--space-3) 0;font-weight:500;">${title}</h2>

      <form id="cat-form" style="max-width:700px;">
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:var(--space-3);margin-bottom:var(--space-4);">
          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">ID interno * ${isEdit ? '(immutable)' : ''}</label>
            <input type="text" name="id" value="${escapeHtml(values.id)}" required ${idReadonly} ${idTooltip} placeholder="itm_wmk_001" pattern="^itm_[a-z0-9_]{3,30}$" title="Formato: itm_ + slug alfanumérico" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:var(--font-mono);font-size:var(--size-sm);">
            ${!isEdit ? '<div style="font-size:var(--size-xs);color:var(--muted);margin-top:var(--space-1);">Formato: itm_ + slug. Ej: itm_wmk_001</div>' : ''}
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">SKU *</label>
            <input type="text" name="sku" value="${escapeHtml(values.sku)}" required minlength="2" placeholder="WMK.001" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Nombre *</label>
            <input type="text" name="name" value="${escapeHtml(values.name)}" required minlength="2" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Categoría *</label>
            <select name="category" required style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;background:#fff;">
              <option value="">Seleccionar...</option>
              ${ITEM_CATEGORIES.map(c => `<option value="${c}" ${values.category === c ? 'selected' : ''}>${escapeHtml(label(`item_category.${c}`) || c)}</option>`).join('')}
            </select>
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Unidad *</label>
            <select name="unit" required style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;background:#fff;">
              ${UNITS.map(u => `<option value="${u}" ${values.unit === u ? 'selected' : ''}>${escapeHtml(label(`unit_of_measure.${u}`) || u)}</option>`).join('')}
            </select>
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Proveedor habitual</label>
            <select name="supplier_id" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;background:#fff;">
              <option value="">Ninguno</option>
              ${supplierOptions}
            </select>
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Umbral mínimo *</label>
            <input type="number" name="min_threshold" value="${values.min_threshold}" required min="0" step="0.01" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Umbral crítico *</label>
            <input type="number" name="critical_threshold" value="${values.critical_threshold}" required min="0" step="0.01" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Plazo entrega (días) *</label>
            <input type="number" name="standard_lead_time_days" value="${values.standard_lead_time_days}" required min="1" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Días de margen (vacío = auto)</label>
            <input type="number" name="buffer_days" value="${values.buffer_days}" min="0" placeholder="Auto según origen" style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Origen *</label>
            <select name="origin_type" required style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;background:#fff;">
              ${ORIGIN_TYPES.map(o => `<option value="${o}" ${values.origin_type === o ? 'selected' : ''}>${escapeHtml(label(`origin_type.${o}`) || o)}</option>`).join('')}
            </select>
          </div>

          <div style="grid-column:1/-1;">
            <label style="display:flex;align-items:center;gap:var(--space-2);font-size:var(--size-sm);cursor:pointer;">
              <input type="checkbox" name="is_shopify_master" ${values.is_shopify_master ? 'checked' : ''} style="width:auto;">
              <span>Master en Shopify</span>
            </label>
          </div>

          <div>
            <label style="display:block;font-size:var(--size-xs);color:var(--muted);margin-bottom:var(--space-1);">Variant ID Shopify</label>
            <input type="text" name="shopify_variant_id" value="${escapeHtml(values.shopify_variant_id)}" ${shopifyDisabled} placeholder="gid://shopify/ProductVariant/..." style="width:100%;padding:var(--space-2);border:1px solid var(--border);font-family:inherit;font-size:var(--size-sm);">
          </div>

          <div style="grid-column:1/-1;">
            <label style="display:flex;align-items:center;gap:var(--space-2);font-size:var(--size-sm);cursor:pointer;">
              <input type="checkbox" name="active" ${values.active ? 'checked' : ''} style="width:auto;">
              <span>Activo</span>
            </label>
          </div>
        </div>

        <div id="cat-form-errors" style="color:var(--danger);font-size:var(--size-sm);margin-bottom:var(--space-3);"></div>

        <button type="submit" class="btn btn-primary">${LABELS.save}</button>
        <button type="button" class="btn btn-secondary" id="cat-btn-cancel">${LABELS.cancel}</button>
      </form>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   BOM VIEW
   ═══════════════════════════════════════════════════════════════════ */

function renderBomView() {
  const item = state.items.find(x => x.id === state.selectedId);
  if (!item) return '<div style="padding:var(--space-4);">Artículo no encontrado.</div>';

  const bom = item.bom || [];
  const flow = item.standard_flow || [];

  const bomRows = bom.map((b, idx) => `
    <tr data-bom-idx="${idx}">
      <td><input type="text" class="bom-component" value="${escapeHtml(b.component_id || '')}" placeholder="SKU componente" style="width:100%;padding:var(--space-1);border:1px solid var(--border);font-family:var(--font-mono);font-size:var(--size-sm);"></td>
      <td><input type="number" class="bom-qty" value="${b.qty || 1}" min="0.01" step="0.01" style="width:80px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="text" class="bom-unit" value="${escapeHtml(b.unit || 'units')}" style="width:100px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="checkbox" class="bom-optional" ${b.optional ? 'checked' : ''} style="width:auto;"></td>
      <td><button type="button" class="btn btn-danger btn-sm bom-remove" style="padding:2px 8px;font-size:var(--size-xs);">×</button></td>
    </tr>
  `).join('');

  const flowRows = flow.map((f, idx) => `
    <tr data-flow-idx="${idx}">
      <td>${idx + 1}</td>
      <td>
        <select class="flow-actor-type" style="padding:var(--space-1);border:1px solid var(--border);">
          <option value="supplier" ${f.actor_type === 'supplier' ? 'selected' : ''}>Proveedor</option>
          <option value="artisan_external" ${f.actor_type === 'artisan_external' ? 'selected' : ''}>Artesano ext.</option>
          <option value="artisan_internal" ${f.actor_type === 'artisan_internal' ? 'selected' : ''}>Artesano int.</option>
        </select>
      </td>
      <td><input type="text" class="flow-actor" value="${escapeHtml(f.actor || '')}" placeholder="Nombre o ID" style="width:100%;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="text" class="flow-action" value="${escapeHtml(f.action || '')}" placeholder="ej: Corte" style="width:100%;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="number" class="flow-eta" value="${f.eta_days || ''}" min="0" style="width:60px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><button type="button" class="btn btn-danger btn-sm flow-remove" style="padding:2px 8px;font-size:var(--size-xs);">×</button></td>
    </tr>
  `).join('');

  return `
    <div id="catalog-bom-view">
      <button type="button" class="btn btn-secondary" id="cat-btn-back-bom" style="margin-bottom:var(--space-2);">← Volver a ${escapeHtml(item.name)}</button>
      <h2 style="margin:0 0 var(--space-3) 0;font-weight:500;">BOM — ${escapeHtml(item.sku)}</h2>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Componentes</h4>
        <table style="width:100%;border-collapse:collapse;font-size:var(--size-sm);">
          <thead>
            <tr style="border-bottom:1px solid var(--border);">
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Componente (SKU)</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Cantidad</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Unidad</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Opcional</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="bom-components-body">
            ${bomRows || '<tr class="bom-empty"><td colspan="5" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin componentes. Añade el primero.</td></tr>'}
          </tbody>
        </table>
        <button type="button" class="btn btn-secondary" id="cat-btn-add-component" style="margin-top:var(--space-2);">+ Añadir componente</button>
      </div>

      <div class="member-block" style="margin-bottom:var(--space-3);padding:var(--space-3);border:1px solid var(--border);">
        <h4 style="margin:0 0 var(--space-2) 0;font-weight:500;font-size:var(--size-sm);color:var(--text-muted);text-transform:uppercase;letter-spacing:0.05em;">Flujo estándar</h4>
        <table style="width:100%;border-collapse:collapse;font-size:var(--size-sm);">
          <thead>
            <tr style="border-bottom:1px solid var(--border);">
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">#</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Tipo actor</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Actor</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Acción</th>
              <th style="text-align:left;padding:var(--space-1);font-weight:500;">Días</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="bom-flow-body">
            ${flowRows || '<tr class="flow-empty"><td colspan="6" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin pasos definidos.</td></tr>'}
          </tbody>
        </table>
        <button type="button" class="btn btn-secondary" id="cat-btn-add-step" style="margin-top:var(--space-2);">+ Añadir paso</button>
      </div>

      <div id="cat-bom-errors" style="color:var(--danger);font-size:var(--size-sm);margin-bottom:var(--space-3);"></div>

      <button type="button" class="btn btn-primary" id="cat-btn-save-bom">Guardar BOM</button>
      <button type="button" class="btn btn-secondary" id="cat-btn-cancel-bom">Cancelar</button>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   EVENT HANDLERS
   ═══════════════════════════════════════════════════════════════════ */

function initListEvents(root) {
  root.querySelectorAll('.filter-pill').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const filter = e.currentTarget.dataset.filter;
      if (filter === 'lowstock') {
        state.filterLowStock = !state.filterLowStock;
      } else {
        state.filterCategory = filter;
        state.filterLowStock = false;
      }
      refreshList(root);
      initListEvents(root);
    });
  });

  const searchInput = root.querySelector('#cat-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value;
      refreshList(root);
    });
  }

  root.querySelector('#cat-btn-create')?.addEventListener('click', () => {
    state.view = 'create';
    state.selectedId = null;
    refreshContent(root);
  });

  root.querySelector('#cat-btn-bootstrap')?.addEventListener('click', () => {
    state.view = 'create';
    state.selectedId = null;
    refreshContent(root);
  });

  root.querySelector('#cat-btn-refresh')?.addEventListener('click', async () => {
    await loadItems(root);
  });

  root.querySelectorAll('.card[data-item-id]').forEach(card => {
    card.addEventListener('click', async () => {
      state.view = 'detail';
      state.selectedId = card.dataset.itemId;
      await refreshContent(root);
    });
  });
}

function initDetailEvents(root) {
  root.querySelector('#cat-btn-back')?.addEventListener('click', () => {
    state.view = 'list';
    state.selectedId = null;
    refreshContent(root);
  });

  root.querySelector('#cat-btn-edit')?.addEventListener('click', () => {
    state.view = 'edit';
    refreshContent(root);
  });

  root.querySelector('#cat-btn-bom')?.addEventListener('click', () => {
    state.view = 'bom';
    refreshContent(root);
  });

  root.querySelector('#cat-btn-delete')?.addEventListener('click', async () => {
    const item = state.items.find(x => x.id === state.selectedId);
    if (!item) return;
    const confirmed = await confirmModal('Eliminar artículo', `¿Eliminar "${item.name}" (${item.sku})? Esta acción desactiva el artículo.`, 'Eliminar', true);
    if (!confirmed) return;
    try {
      await api(`/items/${encodeURIComponent(item.sku)}`, { method: 'DELETE' });
      toast('Artículo eliminado.');
      state.view = 'list';
      state.selectedId = null;
      await refreshContent(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

function initFormEvents(root) {
  root.querySelector('#cat-btn-back-form')?.addEventListener('click', () => {
    state.view = state.selectedId ? 'detail' : 'list';
    refreshContent(root);
  });

  root.querySelector('#cat-btn-cancel')?.addEventListener('click', () => {
    state.view = state.selectedId ? 'detail' : 'list';
    refreshContent(root);
  });

  const shopifyCb = root.querySelector('[name="is_shopify_master"]');
  if (shopifyCb) {
    shopifyCb.addEventListener('change', (e) => {
      const variantInput = root.querySelector('[name="shopify_variant_id"]');
      if (variantInput) {
        variantInput.disabled = !e.target.checked;
        variantInput.style.background = e.target.checked ? '' : 'var(--border)';
      }
    });
  }

  const form = root.querySelector('#cat-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errors = validateForm(form);
      const errDiv = root.querySelector('#cat-form-errors');
      if (errors.length) {
        errDiv.innerHTML = errors.map(err => `• ${err}`).join('<br>');
        return;
      }
      errDiv.innerHTML = '';

      const body = buildBodyFromForm(form);
      const isEdit = state.view === 'edit';
      try {
        if (isEdit) {
          const item = state.items.find(x => x.id === state.selectedId);
          await api(`/items/${encodeURIComponent(item.sku)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          toast('Artículo actualizado.');
          state.view = 'detail';
        } else {
          await api('/items', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          toast('Artículo creado.');
          state.view = 'list';
          state.selectedId = null;
        }
        await refreshContent(root);
      } catch (err) {
        toast(err.message, 'error');
      }
    });
  }
}

function initBomEvents(root) {
  root.querySelector('#cat-btn-back-bom')?.addEventListener('click', () => {
    state.view = 'detail';
    refreshContent(root);
  });

  root.querySelector('#cat-btn-cancel-bom')?.addEventListener('click', () => {
    state.view = 'detail';
    refreshContent(root);
  });

  // Add component row
  root.querySelector('#cat-btn-add-component')?.addEventListener('click', () => {
    const tbody = root.querySelector('#bom-components-body');
    const emptyRow = tbody.querySelector('.bom-empty');
    if (emptyRow) emptyRow.remove();
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input type="text" class="bom-component" placeholder="SKU componente" style="width:100%;padding:var(--space-1);border:1px solid var(--border);font-family:var(--font-mono);font-size:var(--size-sm);"></td>
      <td><input type="number" class="bom-qty" value="1" min="0.01" step="0.01" style="width:80px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="text" class="bom-unit" value="units" style="width:100px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="checkbox" class="bom-optional" style="width:auto;"></td>
      <td><button type="button" class="btn btn-danger btn-sm bom-remove" style="padding:2px 8px;font-size:var(--size-xs);">×</button></td>
    `;
    tbody.appendChild(tr);
    tr.querySelector('.bom-remove').addEventListener('click', () => {
      tr.remove();
      if (!tbody.querySelectorAll('tr').length) {
        tbody.innerHTML = '<tr class="bom-empty"><td colspan="5" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin componentes. Añade el primero.</td></tr>';
      }
    });
  });

  // Add flow row
  root.querySelector('#cat-btn-add-step')?.addEventListener('click', () => {
    const tbody = root.querySelector('#bom-flow-body');
    const emptyRow = tbody.querySelector('.flow-empty');
    if (emptyRow) emptyRow.remove();
    const idx = tbody.querySelectorAll('tr').length;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${idx + 1}</td>
      <td>
        <select class="flow-actor-type" style="padding:var(--space-1);border:1px solid var(--border);">
          <option value="supplier">Proveedor</option>
          <option value="artisan_external">Artesano ext.</option>
          <option value="artisan_internal">Artesano int.</option>
        </select>
      </td>
      <td><input type="text" class="flow-actor" placeholder="Nombre o ID" style="width:100%;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="text" class="flow-action" placeholder="ej: Corte" style="width:100%;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><input type="number" class="flow-eta" min="0" style="width:60px;padding:var(--space-1);border:1px solid var(--border);"></td>
      <td><button type="button" class="btn btn-danger btn-sm flow-remove" style="padding:2px 8px;font-size:var(--size-xs);">×</button></td>
    `;
    tbody.appendChild(tr);
    tr.querySelector('.flow-remove').addEventListener('click', () => {
      tr.remove();
      if (!tbody.querySelectorAll('tr').length) {
        tbody.innerHTML = '<tr class="flow-empty"><td colspan="6" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin pasos definidos.</td></tr>';
      }
      // Re-number
      tbody.querySelectorAll('tr').forEach((row, i) => {
        const numCell = row.querySelector('td:first-child');
        if (numCell) numCell.textContent = i + 1;
      });
    });
  });

  // Existing remove buttons
  root.querySelectorAll('.bom-remove').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const tr = e.target.closest('tr');
      const tbody = root.querySelector('#bom-components-body');
      tr.remove();
      if (!tbody.querySelectorAll('tr').length) {
        tbody.innerHTML = '<tr class="bom-empty"><td colspan="5" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin componentes. Añade el primero.</td></tr>';
      }
    });
  });

  root.querySelectorAll('.flow-remove').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const tr = e.target.closest('tr');
      const tbody = root.querySelector('#bom-flow-body');
      tr.remove();
      if (!tbody.querySelectorAll('tr').length) {
        tbody.innerHTML = '<tr class="flow-empty"><td colspan="6" style="padding:var(--space-3);color:var(--muted);text-align:center;">Sin pasos definidos.</td></tr>';
      }
      tbody.querySelectorAll('tr').forEach((row, i) => {
        const numCell = row.querySelector('td:first-child');
        if (numCell) numCell.textContent = i + 1;
      });
    });
  });

  // Save BOM
  root.querySelector('#cat-btn-save-bom')?.addEventListener('click', async () => {
    const item = state.items.find(x => x.id === state.selectedId);
    if (!item) return;

    const components = [];
    root.querySelectorAll('#bom-components-body tr').forEach(tr => {
      if (tr.classList.contains('bom-empty')) return;
      const id = tr.querySelector('.bom-component')?.value.trim();
      const qty = parseFloat(tr.querySelector('.bom-qty')?.value) || 0;
      if (!id || qty <= 0) return;
      components.push({
        component_id: id,
        qty: qty,
        unit: tr.querySelector('.bom-unit')?.value.trim() || 'units',
        optional: tr.querySelector('.bom-optional')?.checked || false
      });
    });

    const standard_flow = [];
    root.querySelectorAll('#bom-flow-body tr').forEach(tr => {
      if (tr.classList.contains('flow-empty')) return;
      const actor = tr.querySelector('.flow-actor')?.value.trim();
      const action = tr.querySelector('.flow-action')?.value.trim();
      if (!actor || !action) return;
      standard_flow.push({
        actor_type: tr.querySelector('.flow-actor-type')?.value || 'supplier',
        actor: actor,
        action: action,
        eta_days: parseInt(tr.querySelector('.flow-eta')?.value) || 0
      });
    });

    try {
      await api(`/items/${encodeURIComponent(item.sku)}/bom`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bom: components, standard_flow })
      });
      toast('BOM guardado.');
      state.view = 'detail';
      await refreshContent(root);
    } catch (err) {
      toast(err.message, 'error');
    }
  });
}

/* ═══════════════════════════════════════════════════════════════════
   VALIDATION & FORM BUILDER
   ═══════════════════════════════════════════════════════════════════ */

function validateForm(form) {
  const errors = [];
  const id = form.querySelector('[name="id"]').value.trim();
  const sku = form.querySelector('[name="sku"]').value.trim();
  const name = form.querySelector('[name="name"]').value.trim();
  const category = form.querySelector('[name="category"]').value;
  const unit = form.querySelector('[name="unit"]').value;
  const minT = parseFloat(form.querySelector('[name="min_threshold"]').value);
  const critT = parseFloat(form.querySelector('[name="critical_threshold"]').value);
  const lead = parseFloat(form.querySelector('[name="standard_lead_time_days"]').value);
  const origin = form.querySelector('[name="origin_type"]').value;
  const isShopify = form.querySelector('[name="is_shopify_master"]').checked;
  const variantId = form.querySelector('[name="shopify_variant_id"]').value.trim();

  if (!id || !/^itm_[a-z0-9_]{3,30}$/.test(id)) errors.push('ID: formato itm_ + slug alfanumérico (3-30 chars).');
  if (!sku || sku.length < 2) errors.push('SKU: mínimo 2 caracteres.');
  if (!name || name.length < 2) errors.push('Nombre: mínimo 2 caracteres.');
  if (!category) errors.push('Categoría obligatoria.');
  if (!unit) errors.push('Unidad obligatoria.');
  if (isNaN(minT) || minT < 0) errors.push('Umbral mínimo: número >= 0.');
  if (isNaN(critT) || critT < 0) errors.push('Umbral crítico: número >= 0.');
  if (!isNaN(minT) && !isNaN(critT) && critT > minT) errors.push('Umbral crítico debe ser <= umbral mínimo.');
  if (isNaN(lead) || lead <= 0) errors.push('Plazo entrega: número > 0.');
  if (!origin) errors.push('Origen obligatorio.');
  if (isShopify && !variantId) errors.push('Variant ID Shopify obligatorio si es master.');

  return errors;
}

function buildBodyFromForm(form) {
  const get = (n) => {
    const el = form.querySelector(`[name="${n}"]`);
    if (!el) return '';
    if (el.type === 'checkbox') return el.checked;
    return el.value.trim();
  };
  const getNum = (n) => {
    const el = form.querySelector(`[name="${n}"]`);
    if (!el) return null;
    const v = el.value.trim();
    return v ? parseFloat(v) : null;
  };

  const body = {};
  body.id = get('id');
  body.sku = get('sku');
  body.name = get('name');
  body.category = get('category');
  body.unit = get('unit');
  body.min_threshold = getNum('min_threshold') || 0;
  body.critical_threshold = getNum('critical_threshold') || 0;
  body.standard_lead_time_days = getNum('standard_lead_time_days') || 7;
  body.buffer_days = getNum('buffer_days');
  body.origin_type = get('origin_type');
  body.is_shopify_master = !!get('is_shopify_master');
  body.shopify_variant_id = get('shopify_variant_id') || null;
  body.active = get('active') !== false;

  const supplierId = get('supplier_id');
  if (supplierId) body.supplier_id = supplierId;

  return body;
}

/* ═══════════════════════════════════════════════════════════════════
   DATA OPERATIONS
   ═══════════════════════════════════════════════════════════════════ */

async function loadItems(root) {
  state.isLoading = true;
  refreshList(root);
  try {
    const data = await api('/items');
    state.items = data.items || [];
    state.isLoading = false;
    refreshList(root);
  } catch (err) {
    state.isLoading = false;
    toast(err.message, 'error');
    refreshList(root);
  }
}

async function loadSuppliers(root) {
  try {
    const data = await api('/suppliers');
    state.suppliers = data.suppliers || [];
  } catch (err) {
    // Silently fail — suppliers are optional for dropdowns
  }
}

async function loadCategories(root) {
  try {
    const data = await api('/categories');
    state.categories = data.categories || ITEM_CATEGORIES;
  } catch (err) {
    state.categories = ITEM_CATEGORIES;
  }
}

/* ═══════════════════════════════════════════════════════════════════
   UI REFRESH HELPERS
   ═══════════════════════════════════════════════════════════════════ */

async function refreshContent(root) {
  const container = root.querySelector('#stock-subtab-content');
  if (!container) return;
  container.innerHTML = renderCatalogView();
  if (state.view === 'list') initListEvents(root);
  else if (state.view === 'detail') initDetailEvents(root);
  else if (state.view === 'create' || state.view === 'edit') initFormEvents(root);
  else if (state.view === 'bom') initBomEvents(root);
  if (state.view === 'list') await loadItems(root);
}

function refreshList(root) {
  const content = root.querySelector('#catalog-list-content');
  if (content) content.innerHTML = renderItemRows();
  root.querySelectorAll('.card[data-item-id]').forEach(card => {
    card.addEventListener('click', async () => {
      state.view = 'detail';
      state.selectedId = card.dataset.itemId;
      await refreshContent(root);
    });
  });
}
