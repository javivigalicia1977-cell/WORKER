// stock.js — Shell tab Stock (v1.4 skeleton C.5-B.4a+)
// Sub-tabs: overview (placeholder), suppliers (live), catalog (live), batches (live)

import { LABELS } from '/js/stock-labels.js?v=3';
import { toast, confirmModal } from '/js/ui.js?v=2';

// C.5-B.5: expose UI helpers globally for dynamic sub-modules
if (typeof window !== 'undefined') {
  window.toast = window.toast || toast;
  window.confirmModal = window.confirmModal || confirmModal;
}

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
      const mod = await import('/js/tabs/stock/suppliers-view.js?v=5');
      container.innerHTML = mod.renderSuppliersView();
      await mod.initSuppliers(root);
      const hash = window.location.hash;
      const detailMatch = hash.match(/^#\/stock\/suppliers\/(.+)$/);
      if (detailMatch) {
        mod.setInitialState({ selectedId: decodeURIComponent(detailMatch[1]) });
      }
    } catch (err) {
      console.error('Error cargando suppliers-view:', err);
      container.innerHTML = `<div style="color:var(--danger);padding:var(--space-4);">Error cargando proveedores: ${err.message}</div>`;
    }
  } else if (currentSubTab === 'catalog') {
    try {
      const mod = await import('/js/tabs/stock/catalog-view.js?v=2');
      await mod.initCatalog(root);
    } catch (err) {
      console.error('Error cargando catalog-view:', err);
      container.innerHTML = `<div style="color:var(--danger);padding:var(--space-4);">Error cargando catálogo: ${err.message}</div>`;
    }
  } else if (currentSubTab === 'batches') {
    try {
      const mod = await import('/js/tabs/stock/batches-view.js?v=4');
      await mod.initBatches(root);
      const hash = window.location.hash;
      const openMatch = hash.match(/[?&]open=([^&]+)/);
      if (openMatch) {
        const batchId = decodeURIComponent(openMatch[1]);
        // Navegar al detail del batch
        if (mod.setInitialState) {
          mod.setInitialState({ view: 'detail', selectedId: batchId });
        }
      }
    } catch (err) {
      console.error('Error cargando batches-view:', err);
      container.innerHTML = `<div style="color:var(--danger);padding:var(--space-4);">Error cargando lotes: ${err.message}</div>`;
    }
  } else if (currentSubTab === 'overview') {
    try {
      const mod = await import('/js/tabs/stock/overview-view.js?v=7');
      container.innerHTML = mod.renderOverviewView();
      await mod.initOverview(container);
    } catch (err) {
      console.error('Error cargando overview-view:', err);
      container.innerHTML = `<div style="color:var(--danger);padding:var(--space-4);">Error cargando overview: ${err.message}</div>`;
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
