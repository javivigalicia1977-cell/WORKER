// stock.js — Shell tab Stock (v1.1 skeleton C.5-B.2+)
// Sub-tabs: overview (placeholder), suppliers (live), catalog (placeholder), batches (placeholder)

import { LABELS } from '/js/stock-labels.js?v=1';

let currentSubTab = 'overview';
const SUB_TABS = ['overview', 'suppliers', 'catalog', 'batches'];

export function render(root, subPath) {
  if (!root) return;
  currentSubTab = normalizeSubTab(subPath) || getSubTabFromHash() || 'overview';
  root.innerHTML = renderShell();
  loadSubTabContent(root);
  attachEvents(root);
}

function normalizeSubTab(subPath) {
  if (!subPath) return null;
  const clean = subPath.split('/')[0];
  return SUB_TABS.includes(clean) ? clean : null;
}

function getSubTabFromHash() {
  const hash = window.location.hash;
  const match = hash.match(/^#\/stock\/(overview|suppliers|catalog|batches)(?:\/|$)/);
  return match ? match[1] : null;
}

function renderShell() {
  return `
    <header class="tab-header">
      <h1>${LABELS.Stock}</h1>
      <p class="tab-subtitle">Sistema de producción y flujo POTISSE.</p>
    </header>

    <div class="toolbar">
      <div class="toolbar-filters">
        ${renderSubTabPills()}
      </div>
    </div>

    <div id="stock-subtab-content">
      ${renderPlaceholder(currentSubTab)}
    </div>
  `;
}

function renderSubTabPills() {
  const labels = {
    overview: 'Overview',
    suppliers: LABELS.suppliers,
    catalog: 'Catálogo',
    batches: LABELS.batches
  };
  return SUB_TABS.map(key => {
    const active = key === currentSubTab ? ' active' : '';
    return `<button type="button" class="filter-pill${active}" data-subtab="${key}">${labels[key]}</button>`;
  }).join('');
}

function renderPlaceholder(subtab) {
  const placeholders = {
    overview: { title: 'Overview — Dashboard', desc: 'Aquí aparecerán alertas restock, batches en curso, acciones sugeridas.', next: 'C.5-B.5' },
    catalog: { title: 'Catálogo', desc: 'Artículos, BOM (componentes) y pedidos a proveedores.', next: 'C.5-B.3' },
    batches: { title: LABELS.batches, desc: 'Lotes trackeables en el pipeline con timeline de actividad.', next: 'C.5-B.4' }
  };
  const p = placeholders[subtab];
  if (!p) return '';
  return `
    <div class="empty-state" style="text-align:center;padding:var(--space-8);">
      <div style="font-size:3em;opacity:0.3;margin-bottom:var(--space-3);">◯</div>
      <h3 style="margin:0;font-weight:500;color:var(--text);">${p.title}</h3>
      <p style="margin-top:var(--space-2);font-size:var(--size-sm);color:var(--muted);">${p.desc}</p>
      <p style="margin-top:var(--space-4);font-size:var(--size-xs);color:var(--potisse-chocolate-mute);">Próximo push: ${p.next}</p>
    </div>
  `;
}

async function loadSubTabContent(root) {
  const container = root.querySelector('#stock-subtab-content');
  if (!container) return;

  if (currentSubTab === 'suppliers') {
    try {
      const mod = await import('/js/tabs/stock/suppliers-view.js?v=3');
      container.innerHTML = mod.renderSuppliersView();
      mod.initSuppliers(root);
      // Si hay sub-path (ej: suppliers/abc), setear estado
      const hash = window.location.hash;
      const detailMatch = hash.match(/^#\/stock\/suppliers\/(.+)$/);
      if (detailMatch) {
        mod.setInitialState({ selectedId: decodeURIComponent(detailMatch[1]) });
      }
    } catch (err) {
      console.error('Error cargando suppliers-view:', err);
      container.innerHTML = `<div style="color:var(--danger);padding:var(--space-4);">Error cargando proveedores: ${err.message}</div>`;
    }
  } else {
    container.innerHTML = renderPlaceholder(currentSubTab);
  }
}

function attachEvents(root) {
  const pills = root.querySelectorAll('button[data-subtab]');
  pills.forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const subtab = e.currentTarget.dataset.subtab;
      if (subtab === currentSubTab) return;
      currentSubTab = subtab;
      window.history.replaceState(null, '', `#/stock/${subtab}`);
      const filters = root.querySelector('.toolbar-filters');
      if (filters) filters.innerHTML = renderSubTabPills();
      await loadSubTabContent(root);
      attachEvents(root);
    });
  });
}
