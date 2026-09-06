// ═══════════════════════════════════════════════════════════════════════
// POTISSE — constructor.js  (Constructor de Producción / Routing Editor)
// Sprint P4 UI — Sub-tab dentro de Products
// Master-detail: lista fases izquierda + editor fase derecha
// v1.1 — P4.1 Fixes: volver, defaults, consume redesign, SKU search
// ═══════════════════════════════════════════════════════════════════════

import { api } from '/js/api.js?v=2';
import { fmtDate, escapeHtml, timeAgo, debounce } from '/js/utils.js';
import { confirmModal, toast } from '/js/ui.js';

let currentRoot = null;
let state = {
  productId: null,
  product: null,
  routing: [],
  originalRouting: null,
  stockItems: [],
  suppliers: [],
  locations: [],
  selectedPhaseIdx: 0,
  dirty: false,
  loading: false,
};

const PHASE_TYPES = [
  { value: 'purchase', label: 'Compra', icon: 'ti-shopping-cart' },
  { value: 'work', label: 'Trabajo', icon: 'ti-tool' },
  { value: 'logistics', label: 'Logística', icon: 'ti-truck' },
];

const PROVIDERS = ['potisse', 'artesano'];
const CONSUMPTION_MODES = [
  { value: 'directo', label: 'Directo' },
  { value: 'bobina_prestamo', label: 'Bobina préstamo' },
];

const CAPACITY_10_SUPPLIERS = ['sup_composturas_arag_n_eej5', 'sup_estrella_aragonesa_b_i5ro'];

// ── Entry point ──
export async function render(root, productId) {
  currentRoot = root;
  state.productId = productId;
  state.selectedPhaseIdx = 0;
  state.dirty = false;
  state.loading = true;

  root.innerHTML = `
    <div class="constructor-shell">
      <div class="constructor-header">
        <div class="constructor-title-block">
          <div class="constructor-thumb" id="ct-thumb"></div>
          <div>
            <h2 class="constructor-title" id="ct-title">Cargando…</h2>
            <div class="constructor-subtitle" id="ct-subtitle"></div>
          </div>
          <div class="constructor-custom-sizes" id="ct-custom-sizes" style="margin-left:var(--space-4); font-size:var(--size-sm);">
            <!-- populated by renderHeader -->
          </div>
        </div>
        <div class="constructor-actions">
          <button type="button" class="btn btn-sm btn-secondary" id="ct-back">← Volver</button>
          <span class="constructor-dirty-badge" id="ct-dirty" style="display:none;"></span>
          <button type="button" class="btn btn-primary" id="ct-save" disabled>Guardar cambios</button>
        </div>
      </div>
      <div class="constructor-body">
        <div class="constructor-sidebar" id="ct-sidebar"></div>
        <div class="constructor-panel" id="ct-panel">
          <div class="empty-state"><p class="empty-state-text">Cargando routing…</p></div>
        </div>
      </div>
    </div>
  `;

  window.addEventListener('beforeunload', handleBeforeUnload);

  currentRoot.querySelector('#ct-save')?.addEventListener('click', handleSave);
  currentRoot.querySelector('#ct-back')?.addEventListener('click', handleBack);

  // B3: handlers para radios de tallas (bindeados directo en renderHeader)

  try {
    const [productRes, itemsRes, suppliersRes, locationsRes, sizesRes, presetsRes] = await Promise.all([
      api.get(`products/${encodeURIComponent(productId)}`),
      api.get('stock/items'),
      api.get('stock/suppliers'),
      api.get('locations'),
      api.get('config/sizes').catch(() => ({ sizes: ['XS','S','M','L','XL','2XL'] })),
      api.get('presets?active=true').catch(() => ({ presets: [] })),
    ]);

    state.product = productRes.product || null;
    state.routing = (state.product?.production_routing || []).map((ph, i) => ({
      ...ph,
      step_id: ph.step_id || (i + 1),
    }));
    state.stockItems = itemsRes.items || [];
    state.suppliers = suppliersRes.suppliers || [];
    state.locations = locationsRes.locations || [];
    state.globalSizes = sizesRes.sizes || ['XS','S','M','L','XL','2XL'];
    state.customSizes = state.product?.custom_sizes || null;
    state.presets = presetsRes.presets || [];
    state.loading = false;
    // B3: snapshot AFTER customSizes is loaded so comparison is correct
    state.originalSnapshot = JSON.stringify({ routing: state.routing, customSizes: state.customSizes });

    renderHeader();
    renderSidebar();
    renderPanel();
  } catch (err) {
    console.error('[Constructor] Error cargando:', err);
    currentRoot.querySelector('#ct-panel').innerHTML = `
      <div class="empty-state">
        <p class="empty-state-text">${escapeHtml(err.message || 'Error cargando routing.')}</p>
        <button type="button" class="btn btn-sm btn-secondary" id="ct-retry" style="margin-top: var(--space-3);">Reintentar</button>
      </div>
    `;
    currentRoot.querySelector('#ct-retry')?.addEventListener('click', () => render(root, productId));
  }
}

function handleBeforeUnload(e) {
  if (state.dirty) {
    e.preventDefault();
    e.returnValue = 'Tienes cambios sin guardar en el routing. ¿Salir?';
  }
}

async function handleBack() {
  if (state.dirty) {
    const ok = await confirmModal('Cambios sin guardar. ¿Salir sin guardar?');
    if (!ok) return;
  }
  window.location.hash = '#/products/catalog';
}

// ── Dirty state ──
function checkDirty() {
  const current = JSON.stringify({ routing: state.routing, customSizes: state.customSizes });
  state.dirty = current !== state.originalSnapshot;
  updateDirtyBadge();
}

function updateDirtyBadge() {
  const badge = currentRoot.querySelector('#ct-dirty');
  const saveBtn = currentRoot.querySelector('#ct-save');
  if (!badge || !saveBtn) return;

  if (state.dirty) {
    const changes = countChanges();
    badge.style.display = 'inline-flex';
    badge.textContent = `${changes} cambio${changes > 1 ? 's' : ''} sin guardar`;
    saveBtn.disabled = false;
  } else {
    badge.style.display = 'none';
    saveBtn.disabled = true;
  }
}

function countChanges() {
  const snap = state.originalSnapshot ? JSON.parse(state.originalSnapshot) : { routing: [], customSizes: null };
  const orig = snap.routing || [];
  let count = 0;
  if (state.routing.length !== orig.length) {
    count += Math.abs(state.routing.length - orig.length);
  }
  state.routing.forEach((ph, i) => {
    if (i >= orig.length) { count++; return; }
    if (JSON.stringify(ph) !== JSON.stringify(orig[i])) count++;
  });
  return count || 1;
}

// ── Header ──
function getEffectiveSizes() {
  return (state.customSizes && state.customSizes.length > 0) ? state.customSizes : state.globalSizes;
}

function renderHeader() {
  const product = state.product;
  const thumbEl = currentRoot.querySelector('#ct-thumb');
  const titleEl = currentRoot.querySelector('#ct-title');
  const subEl = currentRoot.querySelector('#ct-subtitle');

  const thumbSrc = product?.images?.[0]?.src;
  if (thumbSrc) {
    thumbEl.innerHTML = `<img src="${escapeHtml(thumbSrc)}" alt="" width="40" height="40" onerror="this.style.display='none';this.parentElement.innerHTML='<i class=\'ti ti-package\'></i>';">`;
  } else {
    thumbEl.innerHTML = '<i class="ti ti-package"></i>';
  }

  titleEl.textContent = product?.title || 'Producto';
  subEl.textContent = `Routing · ${state.routing.length} fase${state.routing.length !== 1 ? 's' : ''}`;

  const sizesEl = currentRoot.querySelector('#ct-custom-sizes');
  if (sizesEl) {
    const sizesLabel = (state.customSizes || state.globalSizes).join(', ');
    const isCustom = !!state.customSizes;
    sizesEl.innerHTML = `
      <details ${isCustom ? 'open' : ''}>
        <summary style="cursor:pointer; color:var(--potisse-chocolate-mute);">
          Tallas: <strong>${escapeHtml(sizesLabel)}</strong>
          ${isCustom ? '<span style="color:var(--potisse-cognac); font-size:var(--size-xs);"> (custom)</span>' : '<span style="color:var(--muted); font-size:var(--size-xs);"> (globales)</span>'}
        </summary>
        <div style="margin-top:var(--space-2); padding:var(--space-3); background:var(--potisse-cream); border-radius:var(--radius-md); min-width:280px;">
          <label style="display:block; margin-bottom:var(--space-1);">
            <input type="radio" name="ct-sizes-mode" value="global" ${!isCustom ? 'checked' : ''} id="ct-sizes-mode-global">
            Usar globales (${escapeHtml(state.globalSizes.join(', '))})
          </label>
          <label style="display:block; margin-bottom:var(--space-1);">
            <input type="radio" name="ct-sizes-mode" value="custom" ${isCustom ? 'checked' : ''} id="ct-sizes-mode-custom">
            Custom para este producto
          </label>
          <div id="ct-custom-sizes-editor" style="${isCustom ? '' : 'display:none;'} margin-top:var(--space-2);">
            <input type="text" class="form-input" id="ct-custom-sizes-input"
                   value="${escapeHtml((state.customSizes || []).join(', '))}"
                   placeholder="Ej: XS, S, M, L, XL, 2XL, 3XL"
                   style="width:100%;">
            <p class="constructor-field-hint">Separa tallas con coma. Se guardarán en mayúsculas.</p>
          </div>
        </div>
      </details>
    `;

    // FIX B3: bind directo a radios (delegation en currentRoot no funciona porque apunta a DOM viejo)
    sizesEl.querySelectorAll('[name="ct-sizes-mode"]').forEach(r => {
      r.addEventListener('change', handleSizesRadioChange);
    });
    const customInput = sizesEl.querySelector('#ct-custom-sizes-input');
    if (customInput) customInput.addEventListener('input', handleSizesInputChange);
  }
}

// ── Sidebar (fases list) ──
function renderSidebar() {
  const sidebar = currentRoot.querySelector('#ct-sidebar');
  const phases = state.routing;

  sidebar.innerHTML = `
    <div class="constructor-sidebar-header">
      <span class="constructor-sidebar-title">Fases</span>
      <span class="constructor-sidebar-count">${phases.length}</span>
    </div>
    <div class="constructor-phase-list">
      ${phases.map((ph, i) => {
        const typeCfg = PHASE_TYPES.find(t => t.value === ph.type) || PHASE_TYPES[0];
        const isActive = i === state.selectedPhaseIdx;
        const consumeCount = (ph.consumes || []).length;
        return `
          <div class="constructor-phase-item ${isActive ? 'constructor-phase-item--active' : ''}" data-idx="${i}">
            <div class="constructor-phase-num">${ph.step_id || i + 1}</div>
            <div class="constructor-phase-info">
              <div class="constructor-phase-name">${escapeHtml(ph.name || `Fase ${i + 1}`)}</div>
              <div class="constructor-phase-meta">
                <i class="ti ${typeCfg.icon}"></i> ${typeCfg.label}
                ${consumeCount > 0 ? `· ${consumeCount} material${consumeCount > 1 ? 'es' : ''}` : ''}
              </div>
            </div>
            <button type="button" class="btn btn-xs btn-danger constructor-phase-delete" data-action="delete-phase" data-idx="${i}" title="Eliminar fase">
              <i class="ti ti-trash"></i>
            </button>
          </div>
        `;
      }).join('')}
    </div>
    <button type="button" class="btn btn-primary constructor-add-phase" id="ct-add-phase">
      <i class="ti ti-plus"></i> Añadir fase al final
    </button>
  `;

  sidebar.querySelectorAll('.constructor-phase-item').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('[data-action="delete-phase"]')) return;
      state.selectedPhaseIdx = parseInt(item.dataset.idx, 10);
      renderSidebar();
      renderPanel();
    });
  });

  sidebar.querySelectorAll('[data-action="delete-phase"]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const idx = parseInt(btn.dataset.idx, 10);
      const ok = await confirmModal('Eliminar esta fase? Esta acción no afecta batches ya creados. El cambio solo aplica a batches futuros.');
      if (!ok) return;
      state.routing.splice(idx, 1);
      state.routing.forEach((ph, i) => { ph.step_id = i + 1; });
      if (state.selectedPhaseIdx >= state.routing.length) {
        state.selectedPhaseIdx = Math.max(0, state.routing.length - 1);
      }
      checkDirty();
      renderSidebar();
      renderPanel();
    });
  });

  sidebar.querySelector('#ct-add-phase')?.addEventListener('click', () => {
    const newStepId = state.routing.length + 1;
    state.routing.push({
      step_id: newStepId,
      type: 'purchase',
      name: `Fase ${newStepId}`,
      eta_days: 0,
      consumes: [],
      supplier_id: null,
      artisan_id: null,
      origin_location_id: null,
      dest_location_id: null,
      transporter: null,
      tracking: null,
      capacity_per_day: null,
      cost_per_unit_batch: null,
      parallel_to: null,
    });
    state.selectedPhaseIdx = state.routing.length - 1;
    checkDirty();
    renderSidebar();
    renderPanel();
  });
}

// ── Panel (phase editor) ──
function renderPanel() {
  const panel = currentRoot.querySelector('#ct-panel');
  const idx = state.selectedPhaseIdx;
  const phase = state.routing[idx];

  if (!phase) {
    panel.innerHTML = `
      <div class="empty-state">
        <p class="empty-state-text">No hay fases. Añade la primera con el botón de la izquierda.</p>
      </div>
    `;
    return;
  }

  const typeCfg = PHASE_TYPES.find(t => t.value === phase.type) || PHASE_TYPES[0];

  panel.innerHTML = `
    <div class="constructor-phase-editor">
      <div class="constructor-section">
        <h3 class="constructor-section-title">Información básica</h3>
        <div class="constructor-form-row">
          <div class="form-group" style="flex:2;">
            <label>Nombre <span class="required">*</span></label>
            <input type="text" class="form-input" data-field="name" value="${escapeHtml(phase.name || '')}" placeholder="Ej. Compra blanks">
          </div>
          <div class="form-group" style="flex:1;">
            <label>Tipo <span class="required">*</span></label>
            <select class="form-input" data-field="type">
              ${PHASE_TYPES.map(t => `<option value="${t.value}" ${phase.type === t.value ? 'selected' : ''}>${t.label}</option>`).join('')}
            </select>
          </div>
          <div class="form-group" style="flex:1;">
            <label>ETA días <span title="Días laborables desde inicio de fase" style="cursor:help;"><i class="ti ti-help-circle"></i></span></label>
            <input type="number" class="form-input" data-field="eta_days" value="${phase.eta_days || 0}" min="0" step="1" id="ct-eta-days">
          </div>
        </div>
        <div class="form-group">
          <label>Notas fase</label>
          <textarea class="form-input" data-field="notes" rows="2" placeholder="Opcional">${escapeHtml(phase.notes || '')}</textarea>
        </div>
      </div>

      <div class="constructor-section" id="ct-type-specific">
        ${renderTypeSpecific(phase)}
      </div>

      <div class="constructor-section">
        <div class="constructor-section-header">
          <h3 class="constructor-section-title">Materiales que consume esta fase (${(phase.consumes || []).length})</h3>
          <button type="button" class="btn btn-sm btn-secondary" id="ct-add-consume"><i class="ti ti-plus"></i> Añadir material</button>
          <button type="button" class="btn btn-sm btn-secondary" id="ct-use-preset" title="Rellenar consumes desde un preset bordado"><i class="ti ti-template"></i> Usar preset bordado</button>
        </div>
        ${renderConsumesTable(phase)}
      </div>

      <div class="constructor-section constructor-section--collapsed">
        <div class="constructor-collapsible-header" id="ct-toggle-advanced">
          <i class="ti ti-chevron-right"></i>
          <span>Avanzado</span>
        </div>
        <div class="constructor-collapsible-body" id="ct-advanced-body" style="display:none;">
          <div class="form-group">
            <label>Paralelo a (step_id)</label>
            <select class="form-input" data-field="parallel_to">
              <option value="">— Ninguno —</option>
              ${state.routing.filter((_, i) => i < idx).map((ph, i) =>
                `<option value="${ph.step_id}" ${phase.parallel_to === ph.step_id ? 'selected' : ''}>Fase ${ph.step_id}: ${escapeHtml(ph.name || '')}</option>`
              ).join('')}
            </select>
            <p class="constructor-field-hint">Para paralelismo futuro. Deja vacío por ahora.</p>
          </div>
        </div>
      </div>
    </div>
  `;

  bindPanelEvents(phase, idx);
}

function renderTypeSpecific(phase) {
  if (phase.type === 'purchase') {
    return `
      <h3 class="constructor-section-title">Compra</h3>
      <div class="constructor-form-row">
        <div class="form-group" style="flex:1;">
          <label>Proveedor</label>
          <select class="form-input" data-field="supplier_id" id="ct-supplier">
            <option value="">—</option>
            ${state.suppliers.map(s => `<option value="${escapeHtml(s.id)}" ${phase.supplier_id === s.id ? 'selected' : ''}>${escapeHtml(s.name)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group" style="flex:1;">
          <label>Tracking</label>
          <input type="text" class="form-input" data-field="tracking" value="${escapeHtml(phase.tracking || '')}" placeholder="Número seguimiento o URL">
        </div>
      </div>
    `;
  }

  if (phase.type === 'work') {
    return `
      <h3 class="constructor-section-title">Trabajo</h3>
      <div class="constructor-form-row">
        <div class="form-group" style="flex:1;">
          <label>Proveedor / Artesano</label>
          <select class="form-input" data-field="supplier_id" id="ct-supplier">
            <option value="">—</option>
            ${state.suppliers.map(s => `<option value="${escapeHtml(s.id)}" ${phase.supplier_id === s.id ? 'selected' : ''}>${escapeHtml(s.name)}</option>`).join('')}
          </select>
        </div>
        <div class="form-group" style="flex:1;">
          <label>Capacidad por día</label>
          <input type="number" class="form-input" data-field="capacity_per_day" value="${phase.capacity_per_day || ''}" min="0" step="1" placeholder="Unidades/día" id="ct-capacity">
        </div>
        <div class="form-group" style="flex:1;">
          <label>Coste por unidad (€)</label>
          <input type="number" class="form-input" data-field="cost_per_unit_batch" value="${phase.cost_per_unit_batch || ''}" min="0" step="0.01" placeholder="€/ud">
        </div>
      </div>
    `;
  }

  if (phase.type === 'logistics') {
    const locOpts = renderLocationOptions(phase.origin_location_id);
    const destOpts = renderLocationOptions(phase.dest_location_id);
    return `
      <h3 class="constructor-section-title">Logística</h3>
      <div class="constructor-form-row">
        <div class="form-group" style="flex:1;">
          <label>Origen</label>
          <select class="form-input" data-field="origin_location_id">${locOpts}</select>
        </div>
        <div class="form-group" style="flex:1;">
          <label>Destino</label>
          <select class="form-input" data-field="dest_location_id">${destOpts}</select>
        </div>
      </div>
      <div class="constructor-form-row">
        <div class="form-group" style="flex:1;">
          <label>Transportista</label>
          <input type="text" class="form-input" data-field="transporter" value="${escapeHtml(phase.transporter || '')}" placeholder="Ej. GLS, DHL…">
        </div>
        <div class="form-group" style="flex:1;">
          <label>Tracking</label>
          <input type="text" class="form-input" data-field="tracking" value="${escapeHtml(phase.tracking || '')}" placeholder="Número seguimiento">
        </div>
      </div>
    `;
  }

  return '';
}

function renderLocationOptions(selected) {
  let html = '<option value="">—</option>';
  if (state.locations.length) {
    html += '<optgroup label="Ubicaciones">';
    state.locations.forEach(loc => {
      html += `<option value="${escapeHtml(loc)}" ${selected === loc ? 'selected' : ''}>${escapeHtml(loc)}</option>`;
    });
    html += '</optgroup>';
  }
  if (state.suppliers.length) {
    html += '<optgroup label="Proveedores">';
    state.suppliers.forEach(s => {
      html += `<option value="${escapeHtml(s.id)}" ${selected === s.id ? 'selected' : ''}>${escapeHtml(s.name)} (proveedor)</option>`;
    });
    html += '</optgroup>';
  }
  return html;
}

function renderSkuDropdown(selectedSku, consumeIdx) {
  const items = state.stockItems;
  const groups = {};
  items.forEach(it => {
    const sg = it.sub_group || 'Sin grupo';
    if (!groups[sg]) groups[sg] = [];
    groups[sg].push(it);
  });

  const selectedItem = items.find(it => it.id === selectedSku || it.sku === selectedSku);
  const displayText = selectedItem ? `${selectedItem.name || selectedItem.id} · ${selectedItem.id}` : (selectedSku ? `${selectedSku}` : 'Selecciona material…');

  let groupsHtml = '';
  Object.entries(groups).sort((a, b) => a[0].localeCompare(b[0])).forEach(([groupName, groupItems]) => {
    groupsHtml += `
      <div class="constructor-sku-group" data-group="${escapeHtml(groupName)}">
        <div class="constructor-sku-group-header">${escapeHtml(groupName)}</div>
        ${groupItems.map(it => `
          <div class="constructor-sku-option" data-sku="${escapeHtml(it.id)}" data-name="${escapeHtml(it.name || it.id)}">
            <span class="constructor-sku-option-name">${escapeHtml(it.name || it.id)}</span>
            <span class="constructor-sku-option-id">${escapeHtml(it.id)}</span>
          </div>
        `).join('')}
      </div>
    `;
  });

  return `
    <div class="constructor-sku-dropdown-wrap" data-consume-idx="${consumeIdx}">
      <input type="text" class="form-input constructor-sku-display" value="${escapeHtml(displayText)}" readonly placeholder="Selecciona material…">
      <div class="constructor-sku-dropdown" style="display:none;">
        <input type="text" class="form-input constructor-sku-search" placeholder="Buscar material…">
        <div class="constructor-sku-list">${groupsHtml}</div>
      </div>
    </div>
  `;
}

function renderConsumesTable(phase) {
  const consumes = phase.consumes || [];
  if (!consumes.length) {
    return `
      <div class="constructor-empty-consumes">
        <p>No hay materiales</p>
        <p class="constructor-tip">Añade materiales que consume esta fase. Por ejemplo: hilo, entretela, agujas.</p>
      </div>
    `;
  }

  return `
    <table class="constructor-consumes-table">
      <thead>
        <tr>
          <th>Material</th>
          <th>Qty</th>
          <th>Provee</th>
          <th>Modo</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        ${consumes.map((c, i) => {
          const item = state.stockItems.find(it => it.id === c.sku || it.sku === c.sku);
          const unit = c.unit || item?.unit || 'ud';
          return `
            <tr data-consume-idx="${i}">
              <td>
                ${renderSkuDropdown(c.sku, i)}
                ${c.preset_id ? '<span class="chip chip-info" style="margin-left:var(--space-1); font-size:var(--size-xs); background:var(--potisse-cream); color:var(--potisse-chocolate); padding:2px 6px; border-radius:4px;">Preset</span>' : ''}
                ${c.variant_specific ? '<span class="chip chip-info" style="margin-left:var(--space-1); font-size:var(--size-xs); background:var(--potisse-sage-light); color:var(--potisse-sage-dark); padding:2px 6px; border-radius:4px;">Por talla</span>' : ''}
              </td>
              <td>
                <input type="number" class="form-input" data-field="qty_per_unit" value="${c.qty_per_unit || 0}" min="0" step="0.01" style="width:80px;">
                <span class="constructor-unit">${escapeHtml(unit)}</span>
              </td>
              <td>
                <select class="form-input" data-field="provided_by" style="width:100px;">
                  ${PROVIDERS.map(p => `<option value="${p}" ${c.provided_by === p ? 'selected' : ''}>${p === 'potisse' ? 'POTISSE' : 'Artesano'}</option>`).join('')}
                </select>
              </td>
              <td>
                <select class="form-input" data-field="consumption_mode" style="width:120px;">
                  ${CONSUMPTION_MODES.map(m => `<option value="${m.value}" ${c.consumption_mode === m.value ? 'selected' : ''}>${m.label}</option>`).join('')}
                </select>
              </td>
              <td>
                <button type="button" class="btn btn-xs btn-secondary" data-action="edit-consume" title="Editar detalles: merma, condiciones, notas"><i class="ti ti-settings"></i></button>
                <button type="button" class="btn btn-xs btn-danger" data-action="delete-consume" title="Eliminar material"><i class="ti ti-trash"></i></button>
              </td>
            </tr>
          `;
        }).join('')}
      </tbody>
    </table>
  `;
}

function bindPanelEvents(phase, idx) {
  const panel = currentRoot.querySelector('#ct-panel');

  panel.querySelectorAll('[data-field]').forEach(el => {
    // Textareas disparan 'change' solo al blur — usar 'input' garantiza captura antes de guardar
    const evt = (el.tagName === 'TEXTAREA') ? 'input' : 'change';
    el.addEventListener(evt, () => {
      const field = el.dataset.field;
      let value = el.value;
      if (field === 'eta_days' || field === 'capacity_per_day') {
        value = parseInt(value, 10) || 0;
      }
      if (field === 'cost_per_unit_batch') {
        value = value === '' ? null : parseFloat(value);
      }
      if (field === 'type') {
        phase.type = value;
        if (value === 'purchase') {
          phase.artisan_id = null; phase.capacity_per_day = null; phase.cost_per_unit_batch = null;
          phase.origin_location_id = null; phase.dest_location_id = null; phase.transporter = null;
        } else if (value === 'work') {
          phase.origin_location_id = null; phase.dest_location_id = null; phase.transporter = null;
        } else if (value === 'logistics') {
          phase.supplier_id = null; phase.artisan_id = null; phase.capacity_per_day = null; phase.cost_per_unit_batch = null;
        }
        renderPanel();
      } else {
        phase[field] = value;
      }
      checkDirty();
    });
  });

  const supplierSelect = panel.querySelector('#ct-supplier');
  if (supplierSelect) {
    supplierSelect.addEventListener('change', () => {
      const sid = supplierSelect.value;
      if (!sid) return;
      const supplier = state.suppliers.find(s => s.id === sid);
      if (!supplier) return;

      const etaInput = panel.querySelector('#ct-eta-days');
      if (etaInput && (etaInput.value === '' || etaInput.value === '0') && supplier.standard_lead_time_days) {
        etaInput.value = supplier.standard_lead_time_days;
        phase.eta_days = supplier.standard_lead_time_days;
        flashInput(etaInput);
      }

      if (phase.type === 'work' && CAPACITY_10_SUPPLIERS.includes(sid)) {
        const capInput = panel.querySelector('#ct-capacity');
        if (capInput && (capInput.value === '' || capInput.value === '0')) {
          capInput.value = 10;
          phase.capacity_per_day = 10;
          flashInput(capInput);
        }
      }

      checkDirty();
    });
  }

  panel.querySelectorAll('.constructor-sku-dropdown-wrap').forEach(wrap => {
    const cIdx = parseInt(wrap.dataset.consumeIdx, 10);
    const display = wrap.querySelector('.constructor-sku-display');
    const dropdown = wrap.querySelector('.constructor-sku-dropdown');
    const search = wrap.querySelector('.constructor-sku-search');
    const list = wrap.querySelector('.constructor-sku-list');

    display?.addEventListener('click', () => {
      const isOpen = dropdown.style.display === 'block';
      document.querySelectorAll('.constructor-sku-dropdown').forEach(d => d.style.display = 'none');
      if (!isOpen) {
        dropdown.style.display = 'block';
        search?.focus();
      }
    });

    search?.addEventListener('input', debounce(() => {
      const q = search.value.toLowerCase();
      list.querySelectorAll('.constructor-sku-group').forEach(grp => {
        let hasMatch = false;
        grp.querySelectorAll('.constructor-sku-option').forEach(opt => {
          const name = (opt.dataset.name || '').toLowerCase();
          const sku = (opt.dataset.sku || '').toLowerCase();
          const match = name.includes(q) || sku.includes(q);
          opt.style.display = match ? '' : 'none';
          if (match) hasMatch = true;
        });
        grp.style.display = hasMatch ? '' : 'none';
      });
    }, 200));

    list.querySelectorAll('.constructor-sku-option').forEach(opt => {
      opt.addEventListener('click', () => {
        const sku = opt.dataset.sku;
        const name = opt.dataset.name;
        phase.consumes[cIdx].sku = sku;
        display.value = `${name} · ${sku}`;
        dropdown.style.display = 'none';
        checkDirty();
      });
    });
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('.constructor-sku-dropdown-wrap')) {
      document.querySelectorAll('.constructor-sku-dropdown').forEach(d => d.style.display = 'none');
    }
  });

  panel.querySelectorAll('.constructor-consumes-table tbody tr').forEach(row => {
    const cIdx = parseInt(row.dataset.consumeIdx, 10);
    row.querySelectorAll('input[data-field], select[data-field]').forEach(el => {
      if (el.closest('.constructor-sku-dropdown-wrap')) return;
      el.addEventListener('change', () => {
        const field = el.dataset.field;
        let value = el.value;
        if (field === 'qty_per_unit') value = parseFloat(value) || 0;
        phase.consumes[cIdx][field] = value;
        checkDirty();
      });
    });

    row.querySelector('[data-action="edit-consume"]')?.addEventListener('click', () => {
      openEditConsumeModal(phase, cIdx);
    });
    row.querySelector('[data-action="delete-consume"]')?.addEventListener('click', async () => {
      const ok = await confirmModal('¿Eliminar este material del consume?');
      if (!ok) return;
      phase.consumes.splice(cIdx, 1);
      checkDirty();
      renderPanel();
    });
  });

  panel.querySelector('#ct-add-consume')?.addEventListener('click', () => {
    openAddConsumeModal(phase, panel);
  });

  panel.querySelector('#ct-use-preset')?.addEventListener('click', () => {
    openPresetSelectorModal(phase);
  });

  panel.querySelector('#ct-toggle-advanced')?.addEventListener('click', () => {
    const body = panel.querySelector('#ct-advanced-body');
    const chevron = panel.querySelector('#ct-toggle-advanced i');
    const isOpen = body.style.display !== 'none';
    body.style.display = isOpen ? 'none' : 'block';
    chevron.classList.toggle('ti-chevron-right', isOpen);
    chevron.classList.toggle('ti-chevron-down', !isOpen);
  });
}

function updateSizesCaption() {
  const summary = currentRoot.querySelector('#ct-custom-sizes summary');
  if (!summary) return;
  const sizesLabel = (state.customSizes || state.globalSizes).join(', ');
  const isCustom = !!state.customSizes;
  summary.innerHTML = `
    Tallas: <strong>${escapeHtml(sizesLabel)}</strong>
    ${isCustom ? '<span style="color:var(--potisse-cognac); font-size:var(--size-xs);"> (custom)</span>' : '<span style="color:var(--muted); font-size:var(--size-xs);"> (globales)</span>'}
  `;
}

function handleSizesRadioChange(e) {
  const editor = currentRoot.querySelector('#ct-custom-sizes-editor');
  const input = currentRoot.querySelector('#ct-custom-sizes-input');
  if (e.target.value === 'global') {
    state.customSizes = null;
    if (editor) editor.style.display = 'none';
  } else {
    if (editor) editor.style.display = 'block';
    const parsed = (input?.value || '').split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
    const unique = [...new Set(parsed)];
    state.customSizes = unique.length > 0 ? unique : state.globalSizes.slice();
    if (input) input.value = state.customSizes.join(', ');
  }
  updateSizesCaption();
  checkDirty();
}

function handleSizesInputChange(e) {
  const parsed = e.target.value.split(',').map(s => s.trim().toUpperCase()).filter(Boolean);
  const unique = [...new Set(parsed)];
  state.customSizes = unique.length > 0 ? unique : null;
  checkDirty();
}

function flashInput(el) {
  el.style.transition = 'background 0.3s ease';
  el.style.background = 'rgba(78,122,90,0.15)';
  setTimeout(() => { el.style.background = ''; }, 300);
}

function openEditConsumeModal(phase, consumeIdx) {
  const c = phase.consumes[consumeIdx];
  const item = state.stockItems.find(it => it.id === c.sku);
  const skuDisplay = item ? `${item.name || item.id} · ${item.id}` : (c.sku || 'Nuevo material');

  const overlay = wrapModal(`
    <div class="modal-header">
      <h3 class="modal-title">Editar detalles del material: ${escapeHtml(skuDisplay)}</h3>
      <button type="button" class="modal-close" data-close>×</button>
    </div>
    <div class="modal-body">
      <p class="constructor-modal-intro">
        Ajustes finos del material: cuánto se pierde por rotura o corte durante la fase,
        si el material es opcional en algunos casos, y notas adicionales para POT.
      </p>

      <div class="form-group">
        <label>% Rotura esperada
          <span title="Cuánto material se pierde por rotura o corte durante la fase. Ejemplo: 0.25 = 25% extra. Si envías etiquetas para 40 camisetas y esperas 25% rotura, enviarás 50 etiquetas." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
        <input type="number" class="form-input" data-field="merma_percent" value="${c.merma_percent || 0}" min="0" max="1" step="0.05" id="ct-merma-input">
        <p class="constructor-field-hint" id="ct-merma-preview"></p>
      </div>

      <div class="form-group">
        <label>% Overhead (sobreestima)
          <span title="Sobreestima aplicada al calcular cantidades del batch. Filosofía POTISSE: mejor que sobre a que falte. Default 20% para presets bordado. Editable por consume." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
        <input type="number" class="form-input" data-field="overhead_percent" value="${((c.overhead_percent || 0) * 100).toFixed(0)}" min="0" max="100" step="1">
        <p class="constructor-field-hint">${c.preset_id ? 'Copiado del preset (editable). Base × (1 + merma) × (1 + overhead) = cantidad final.' : 'Overhead se aplica multiplicativo tras merma. Base × (1 + merma) × (1 + overhead) = cantidad final.'}</p>
      </div>

      <div class="form-group">
        <label>Condición (opcional)
          <span title="Texto libre para POT indicando cuándo aplica este material. Deja vacío si aplica siempre. Ejemplos: 'solo si color = blanco', 'solo si talla = XL'." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
        <input type="text" class="form-input" data-field="condition" value="${escapeHtml(c.condition || '')}" placeholder="ej: solo si talla = XL">
      </div>

      <div class="form-group">
        <label>
          <input type="checkbox" data-field="optional" ${c.optional ? 'checked' : ''}>
          Material opcional
          <span title="Si activado, este material puede ausentarse sin bloquear la fase. Útil para materiales que a veces se usan y a veces no." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
      </div>

      <div class="form-group">
        <label>Notas para POT
          <span title="Cualquier nota adicional que POT deba saber al preparar este material para la fase." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
        <textarea class="form-input" data-field="notes" rows="3" placeholder="Instrucciones especiales, avisos…">${escapeHtml(c.notes || '')}</textarea>
      </div>

      <div class="form-group" style="border-top:1px solid var(--hairline); padding-top:var(--space-3); margin-top:var(--space-3);">
        <label>
          <input type="checkbox" data-field="variant_specific" id="ct-variant-specific-toggle" ${c.variant_specific ? 'checked' : ''}>
          Este material varía por talla
          <span title="Marca esto si el SKU es distinto según la talla. Ejemplo: etiqueta cuello XS es itm_lbl_xs, etiqueta cuello S es itm_lbl_s. Al crear batch con distribución tallas, sistema materializa cantidades correctas por talla." style="cursor:help;">
            <i class="ti ti-help-circle"></i>
          </span>
        </label>
        <p class="constructor-field-hint">
          Al activar esto, defines qué SKU de stock usar para cada talla.
        </p>
      </div>

      <div id="ct-size-family-editor" style="${c.variant_specific ? '' : 'display:none;'} background:var(--potisse-cream); padding:var(--space-3); border-radius:var(--radius-md); margin-top:var(--space-2);">
        <label style="font-weight:600; margin-bottom:var(--space-2); display:block;">SKU por talla</label>
        <div id="ct-size-family-rows">
          ${getEffectiveSizes().map(size => {
            const currentSku = c.size_family?.[size] || '';
            return `
              <div class="ct-size-family-row" style="display:flex; gap:var(--space-2); align-items:center; margin-bottom:var(--space-2);">
                <span style="min-width:40px; font-weight:600; font-family:var(--font-mono);">${escapeHtml(size)}</span>
                <select class="form-input ct-size-family-sku" data-size="${escapeHtml(size)}" style="flex:1;">
                  <option value="">— No aplica esta talla —</option>
                  ${state.stockItems.map(item => `<option value="${escapeHtml(item.id)}" ${currentSku === item.id ? 'selected' : ''}>${escapeHtml(item.name || item.id)} (${escapeHtml(item.id)})</option>`).join('')}
                </select>
              </div>
            `;
          }).join('')}
        </div>
        <p class="constructor-field-hint" style="margin-top:var(--space-2);">
          Deja "No aplica" en tallas donde este material no se use. Al menos una talla debe tener SKU asignado.
        </p>
      </div>
    </div>
    <div class="modal-footer" style="justify-content:space-between;">
      <button type="button" class="btn btn-xs btn-danger" data-action="delete" title="Eliminar este material del consume">
        <i class="ti ti-trash"></i>
      </button>
      <div style="display:flex;gap:var(--space-2);">
        <button type="button" class="btn btn-secondary" data-close>Cancelar</button>
        <button type="button" class="btn btn-primary" data-action="save">Guardar cambios</button>
      </div>
    </div>
  `, 'Editar detalles del material');

  bindClose(overlay);

  const mermaInput = overlay.querySelector('#ct-merma-input');
  const previewEl = overlay.querySelector('#ct-merma-preview');
  function updatePreview() {
    const merma = parseFloat(mermaInput?.value) || 0;
    const baseQty = 40;
    const total = Math.round(baseQty * (1 + merma));
    previewEl.textContent = `Para lote de ${baseQty} uds enviarás ${total} unidades.`;
  }
  mermaInput?.addEventListener('input', updatePreview);
  updatePreview();

  const variantToggle = overlay.querySelector('#ct-variant-specific-toggle');
  const sizeFamilyEditor = overlay.querySelector('#ct-size-family-editor');
  variantToggle?.addEventListener('change', () => {
    if (variantToggle.checked) {
      sizeFamilyEditor.style.display = 'block';
    } else {
      sizeFamilyEditor.style.display = 'none';
    }
  });

  overlay.querySelector('[data-action="save"]')?.addEventListener('click', () => {
    c.merma_percent = parseFloat(overlay.querySelector('[data-field="merma_percent"]')?.value) || 0;
    const overheadPctInput = parseFloat(overlay.querySelector('[data-field="overhead_percent"]')?.value);
    c.overhead_percent = (!isNaN(overheadPctInput) && overheadPctInput >= 0 && overheadPctInput <= 100)
      ? overheadPctInput / 100
      : 0;
    c.condition = overlay.querySelector('[data-field="condition"]')?.value?.trim() || null;
    c.optional = overlay.querySelector('[data-field="optional"]')?.checked || false;
    c.notes = overlay.querySelector('[data-field="notes"]')?.value?.trim() || '';

    const variantChecked = overlay.querySelector('[data-field="variant_specific"]')?.checked || false;
    c.variant_specific = variantChecked;
    if (variantChecked) {
      const sizeFamily = {};
      overlay.querySelectorAll('.ct-size-family-sku').forEach(sel => {
        const size = sel.dataset.size;
        const sku = sel.value?.trim();
        if (size && sku) sizeFamily[size] = sku;
      });
      if (Object.keys(sizeFamily).length === 0) {
        toast('Debes asignar al menos una talla → SKU antes de guardar', 'warning');
        return;
      }
      c.size_family = sizeFamily;
    } else {
      c.size_family = null;
    }

    checkDirty();
    closeOverlay(overlay);
    renderPanel();
  });

  overlay.querySelector('[data-action="delete"]')?.addEventListener('click', async () => {
    const ok = await confirmModal(`¿Eliminar ${escapeHtml(skuDisplay)} del consume de esta fase?`);
    if (!ok) return;
    phase.consumes.splice(consumeIdx, 1);
    checkDirty();
    closeOverlay(overlay);
    renderPanel();
  });
}

async function handleSave() {
  const errors = validateRouting();
  if (errors.length > 0) {
    toast(`Errores de validación: ${errors[0]}`, 'error');
    openErrorsModal(errors);
    return;
  }

  const btn = currentRoot.querySelector('#ct-save');
  btn.disabled = true;
  btn.textContent = 'Guardando…';

  try {
    // B3: cleanup size_family — only keep sizes valid for this product
    const validSizes = getEffectiveSizes();
    const cleanedRouting = state.routing.map(ph => ({
      ...ph,
      consumes: (ph.consumes || []).map(c => {
        if (c.variant_specific && c.size_family) {
          const filtered = {};
          for (const [size, sku] of Object.entries(c.size_family)) {
            if (validSizes.includes(size) && sku && String(sku).trim()) {
              filtered[size] = String(sku).trim();
            }
          }
          return { ...c, size_family: Object.keys(filtered).length > 0 ? filtered : null };
        }
        return c;
      })
    }));

    const body = {
      production_routing: cleanedRouting,
      custom_sizes: state.customSizes || []  // [] = usar globales (backend normaliza a null)
    };
    const res = await api.put(`products/${encodeURIComponent(state.productId)}/routing`, body);
    state.originalSnapshot = JSON.stringify({ routing: state.routing, customSizes: state.customSizes });
    state.dirty = false;
    updateDirtyBadge();
    toast('Routing guardado ✓', 'success');
    btn.textContent = 'Guardar cambios';
  } catch (err) {
    if (err.errors && Array.isArray(err.errors)) {
      openErrorsModal(err.errors);
    } else {
      toast(`Error: ${err.message}`, 'error');
    }
    btn.disabled = false;
    btn.textContent = 'Guardar cambios';
  }
}

function validateRouting() {
  const errors = [];
  state.routing.forEach((ph, i) => {
    const faseLabel = `Fase ${ph.step_id || i + 1}`;
    if (!ph.name || !ph.name.trim()) {
      errors.push(`${faseLabel}: nombre obligatorio`);
    }
    if (!['purchase', 'work', 'logistics'].includes(ph.type)) {
      errors.push(`${faseLabel}: tipo inválido`);
    }
    (ph.consumes || []).forEach((c, ci) => {
      if (!c.sku || !c.sku.trim()) {
        errors.push(`${faseLabel} consume ${ci + 1}: SKU requerido`);
      }
      if (c.qty_per_unit < 0) {
        errors.push(`${faseLabel} consume ${ci + 1}: qty_per_unit debe ser ≥ 0`);
      }
      if (c.merma_percent < 0 || c.merma_percent > 1) {
        errors.push(`${faseLabel} consume ${ci + 1}: merma_percent entre 0 y 1`);
      }
    });
  });
  return errors;
}

function openErrorsModal(errors) {
  const overlay = wrapModal(`
    <div class="modal-header"><h3 class="modal-title">Errores de validación (${errors.length})</h3><button type="button" class="modal-close" data-close>×</button></div>
    <div class="modal-body">
      <div class="constructor-errors-list">
        ${errors.map(e => `<div class="constructor-error-item">${escapeHtml(e)}</div>`).join('')}
      </div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" data-close>Cerrar</button>
    </div>
  `, 'Errores de validación');

  bindClose(overlay);

  overlay.querySelectorAll('.constructor-error-item').forEach(item => {
    item.style.cursor = 'pointer';
    item.addEventListener('click', () => {
      const match = item.textContent.match(/Fase\s+(\d+)/i);
      if (match) {
        const stepId = parseInt(match[1], 10);
        const idx = state.routing.findIndex(ph => ph.step_id === stepId);
        if (idx >= 0) {
          state.selectedPhaseIdx = idx;
          closeOverlay(overlay);
          renderSidebar();
          renderPanel();
        }
      }
    });
  });
}

function createOverlay() {
  const existing = document.querySelector('.constructor-modal-overlay');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay constructor-modal-overlay';
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');

  const esc = (e) => { if (e.key === 'Escape') closeOverlay(overlay); };
  document.addEventListener('keydown', esc);
  overlay._esc = esc;

  document.body.appendChild(overlay);
  return overlay;
}

function closeOverlay(overlay) {
  if (overlay._esc) document.removeEventListener('keydown', overlay._esc);
  overlay.remove();
}

function wrapModal(html, label) {
  const overlay = createOverlay();
  overlay.setAttribute('aria-label', label);
  overlay.innerHTML = `<div class="modal constructor-modal">${html}</div>`;
  const modal = overlay.querySelector('.modal');
  modal.addEventListener('click', (e) => e.stopPropagation());
  return overlay;
}

function bindClose(overlay) {
  overlay.querySelectorAll('[data-close]').forEach(b => {
    b.addEventListener('click', () => closeOverlay(overlay));
  });
}


function openPresetSelectorModal(phase) {
  const presets = (state.presets || []).filter(p => p.type === 'bordado' && p.active !== false);
  if (presets.length === 0) {
    toast('No hay presets bordado activos. Crea uno en Products → Presets bordado', 'warning');
    return;
  }

  const overlay = wrapModal(`
    <div class="modal-header">
      <h3 class="modal-title">Elegir preset bordado</h3>
      <button type="button" class="modal-close" data-close>×</button>
    </div>
    <div class="modal-body">
      <p class="constructor-modal-intro">Al aplicar, se añaden los materiales del preset como consumes de esta fase con overhead preconfigurado.</p>

      <div class="form-group">
        <label>Buscar preset</label>
        <input type="text" class="form-input" id="preset-search" placeholder="Escribe para filtrar...">
      </div>

      <div class="form-group">
        <label>Preset</label>
        <select class="form-input" id="preset-select" size="6" style="height:auto;">
          ${presets.map(p => {
            const matsCount = (p.materials || []).length;
            const overheadPct = ((p.overhead_percent || 0) * 100).toFixed(0);
            return `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} — ${matsCount} materiales · overhead ${overheadPct}%${p.size_ref ? ` · ${p.size_ref}mm` : ''}</option>`;
          }).join('')}
        </select>
      </div>

      <div id="preset-preview" style="display:none; padding:var(--space-3); background:var(--potisse-cream); border-radius:var(--radius-md); margin-top:var(--space-3);">
        <h4 style="margin:0 0 var(--space-2) 0;">Materiales que se añadirán</h4>
        <div id="preset-preview-materials"></div>
      </div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" data-close>Cancelar</button>
      <button type="button" class="btn btn-primary" data-action="apply-preset" disabled>Aplicar preset</button>
    </div>
  `, 'Elegir preset');

  bindClose(overlay);

  const searchInput = overlay.querySelector('#preset-search');
  const selectEl = overlay.querySelector('#preset-select');
  const previewDiv = overlay.querySelector('#preset-preview');
  const previewMats = overlay.querySelector('#preset-preview-materials');
  const applyBtn = overlay.querySelector('[data-action="apply-preset"]');

  searchInput.addEventListener('input', () => {
    const term = searchInput.value.trim().toLowerCase();
    selectEl.querySelectorAll('option').forEach(opt => {
      opt.style.display = opt.textContent.toLowerCase().includes(term) ? '' : 'none';
    });
  });

  selectEl.addEventListener('change', () => {
    const presetId = selectEl.value;
    const preset = presets.find(p => p.id === presetId);
    if (!preset) { previewDiv.style.display = 'none'; applyBtn.disabled = true; return; }

    const matsHtml = (preset.materials || []).map(m => {
      const item = state.stockItems.find(it => it.id === m.sku || it.sku === m.sku);
      const itemName = item?.name || m.sku;
      return `
        <div style="display:flex; justify-content:space-between; padding:4px 0; font-size:0.85rem; border-bottom:1px solid var(--hairline);">
          <span>${escapeHtml(itemName)} <span style="color:var(--muted); font-family:var(--font-mono); font-size:0.75rem;">(${escapeHtml(m.sku)})</span>${m.role ? ` <span style="color:var(--muted);">· ${escapeHtml(m.role)}</span>` : ''}</span>
          <span style="font-family:var(--font-mono);">${m.qty_per_unit}${escapeHtml(m.unit || '')}/ud</span>
        </div>
      `;
    }).join('');
    previewMats.innerHTML = matsHtml;
    previewDiv.style.display = 'block';
    applyBtn.disabled = false;
  });

  applyBtn.addEventListener('click', () => {
    const presetId = selectEl.value;
    const preset = presets.find(p => p.id === presetId);
    if (!preset) return;

    if (!Array.isArray(phase.consumes)) phase.consumes = [];

    for (const m of (preset.materials || [])) {
      phase.consumes.push({
        sku: m.sku,
        qty_per_unit: m.qty_per_unit,
        unit: m.unit,
        provided_by: 'potisse',
        consumption_mode: 'directo',
        optional: false,
        condition: null,
        merma_percent: 0,
        notes: `Añadido desde preset: ${preset.name}`,
        variant_specific: false,
        size_family: null,
        preset_id: preset.id,
        overhead_percent: preset.overhead_percent || 0.20
      });
    }

    toast(`Preset "${preset.name}" aplicado: ${(preset.materials || []).length} materiales añadidos`, 'success');
    closeOverlay(overlay);
    checkDirty();
    renderPanel();
  });
}

// ═══════════════════════════════════════════════════════════════════════
// B2.4 — Selector inteligente: modal 2 pasos para añadir material
// ═══════════════════════════════════════════════════════════════════════

function openAddConsumeModal(phase, panel) {
  let currentStep = 'category';
  let selectedType = null;

  const overlay = wrapModal(renderStep1(), 'Añadir material');
  bindClose(overlay);

  function renderStep1() {
    return `
      <div class="modal-header">
        <h3 class="modal-title">¿Qué tipo de material?</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <div class="modal-body">
        <p style="color:var(--muted); margin:0 0 var(--space-3) 0; font-size:0.85rem;">Elige la categoría para filtrar solo materiales relevantes a esta fase.</p>
        <div style="display:grid; grid-template-columns:1fr; gap:var(--space-2);">
          <button type="button" class="ct-cat-card" data-cat="confeccion" style="display:flex; align-items:center; gap:12px; padding:16px; border:1px solid var(--border); border-radius:6px; background:white; cursor:pointer; text-align:left; font-family:inherit; transition:border-color 0.15s, background 0.15s;">
            <div style="font-size:1.5rem;">🎨</div>
            <div style="flex:1;">
              <div style="font-weight:500; color:var(--potisse-chocolate); margin-bottom:2px;">Confección</div>
              <div style="font-size:0.75rem; color:var(--muted);">Se consume en el producto final (blanks, telas, etiquetas cosidas)</div>
            </div>
          </button>
          <button type="button" class="ct-cat-card" data-cat="packaging" style="display:flex; align-items:center; gap:12px; padding:16px; border:1px solid var(--border); border-radius:6px; background:white; cursor:pointer; text-align:left; font-family:inherit; transition:border-color 0.15s, background 0.15s;">
            <div style="font-size:1.5rem;">📦</div>
            <div style="flex:1;">
              <div style="font-weight:500; color:var(--potisse-chocolate); margin-bottom:2px;">Packaging</div>
              <div style="font-size:0.75rem; color:var(--muted);">Envío al cliente (cajas, tarjetas, stickers, papel seda)</div>
            </div>
          </button>
          <button type="button" class="ct-cat-card" data-cat="artisan_tool" style="display:flex; align-items:center; gap:12px; padding:16px; border:1px solid var(--border); border-radius:6px; background:white; cursor:pointer; text-align:left; font-family:inherit; transition:border-color 0.15s, background 0.15s;">
            <div style="font-size:1.5rem;">🧵</div>
            <div style="flex:1;">
              <div style="font-weight:500; color:var(--potisse-chocolate); margin-bottom:2px;">Herramienta/Artesano</div>
              <div style="font-size:0.75rem; color:var(--muted);">Préstamo al artesano (hilos, estabilizadores, agujas)</div>
            </div>
          </button>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-close>Cancelar</button>
      </div>
    `;
  }

  function renderStep2(materialType) {
    const filteredItems = (state.stockItems || []).filter(it => (it.material_type || 'confeccion') === materialType);

    const groups = {};
    filteredItems.forEach(it => {
      const sg = it.sub_group || 'Sin grupo';
      if (!groups[sg]) groups[sg] = [];
      groups[sg].push(it);
    });

    const sortedGroups = Object.keys(groups).sort();
    const optgroups = sortedGroups.map(sg => {
      const options = groups[sg].map(it =>
        `<option value="${escapeHtml(it.id || it.sku)}">${escapeHtml(it.name || it.id)} — ${escapeHtml(it.sku || it.id)}</option>`
      ).join('');
      return `<optgroup label="${escapeHtml(sg)}">${options}</optgroup>`;
    }).join('');

    const catLabels = { confeccion: '🎨 Confección', packaging: '📦 Packaging', artisan_tool: '🧵 Artesano' };

    return `
      <div class="modal-header">
        <h3 class="modal-title">Elige material · ${catLabels[materialType]}</h3>
        <button type="button" class="modal-close" data-close>×</button>
      </div>
      <div class="modal-body">
        <p style="color:var(--muted); margin:0 0 var(--space-2) 0; font-size:0.85rem;">${filteredItems.length} materiales disponibles en esta categoría.</p>
        <div class="form-group">
          <label>Buscar</label>
          <input type="text" class="form-input" id="ct-add-search" placeholder="SKU o nombre...">
        </div>
        <div class="form-group">
          <label>Material</label>
          <select class="form-input" id="ct-add-sku" size="8" style="height:auto;">
            <option value="">— Selecciona material —</option>
            ${optgroups}
          </select>
          ${filteredItems.length === 0 ? '<p style="color:var(--muted); font-size:0.8rem; margin-top:8px;">No hay materiales de esta categoría. Crea uno primero en Stock → Artículos.</p>' : ''}
        </div>
      </div>
      <div class="modal-footer" style="justify-content:space-between;">
        <button type="button" class="btn btn-secondary" data-action="back">← Volver a categorías</button>
        <div style="display:flex; gap:8px;">
          <button type="button" class="btn btn-secondary" data-close>Cancelar</button>
          <button type="button" class="btn btn-primary" data-action="confirm" disabled>Añadir material</button>
        </div>
      </div>
    `;
  }

  function bindStep(step) {
    if (step === 'category') {
      overlay.querySelectorAll('.ct-cat-card').forEach(btn => {
        btn.addEventListener('click', (e) => {
          selectedType = e.currentTarget.dataset.cat;
          currentStep = 'material';
          overlay.querySelector('.modal').innerHTML = renderStep2(selectedType);
          bindClose(overlay);
          bindStep('material');
        });
        btn.addEventListener('mouseenter', () => {
          btn.style.borderColor = 'var(--potisse-chocolate)';
          btn.style.background = 'var(--potisse-cream)';
        });
        btn.addEventListener('mouseleave', () => {
          btn.style.borderColor = 'var(--border)';
          btn.style.background = 'white';
        });
      });
    } else if (step === 'material') {
      const searchInput = overlay.querySelector('#ct-add-search');
      const skuSelect = overlay.querySelector('#ct-add-sku');
      const confirmBtn = overlay.querySelector('[data-action="confirm"]');

      searchInput?.addEventListener('input', () => {
        const term = searchInput.value.trim().toLowerCase();
        skuSelect.querySelectorAll('option').forEach(opt => {
          if (!opt.value) return;
          opt.style.display = opt.textContent.toLowerCase().includes(term) ? '' : 'none';
        });
        skuSelect.querySelectorAll('optgroup').forEach(og => {
          const visibleOpts = Array.from(og.querySelectorAll('option')).filter(o => o.style.display !== 'none' && o.value);
          og.style.display = visibleOpts.length > 0 ? '' : 'none';
        });
      });

      skuSelect?.addEventListener('change', () => {
        confirmBtn.disabled = !skuSelect.value;
      });

      overlay.querySelector('[data-action="back"]')?.addEventListener('click', () => {
        currentStep = 'category';
        selectedType = null;
        overlay.querySelector('.modal').innerHTML = renderStep1();
        bindClose(overlay);
        bindStep('category');
      });

      confirmBtn?.addEventListener('click', () => {
        const sku = skuSelect.value;
        if (!sku) return;

        if (!phase.consumes) phase.consumes = [];
        phase.consumes.push({
          sku: sku,
          qty_per_unit: 0,
          provided_by: 'potisse',
          consumption_mode: 'directo',
          optional: false,
          condition: null,
          merma_percent: 0,
          notes: '',
          variant_specific: false,
          size_family: null,
          preset_id: null,
          overhead_percent: 0
        });

        const item = state.stockItems.find(it => it.id === sku || it.sku === sku);
        toast(`Material "${item?.name || sku}" añadido a la fase`, 'success');
        closeOverlay(overlay);
        checkDirty();
        renderPanel();
      });
    }
  }

  bindStep('category');
}
