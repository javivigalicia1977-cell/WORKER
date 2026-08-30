// products-bom-worktypes-modal.js — v1.0 (Sprint P2 — Editar work types BOM)
import { api, apiAdmin, escapeHtml } from '/js/tabs/stock/overview-utils.js?v=58';
import { toast } from '/js/ui.js?v=57';

export async function openBomWorkTypesModal(product, root, deps) {
  const { refreshContent } = deps;
  const productId = product.id;

  // Cargar BOM actual para materiales disponibles
  let availableMaterials = [];
  let currentWorkTypes = [];
  try {
    const data = await apiAdmin(`/products/${productId}/bom`);
    availableMaterials = (data.bom?.materials || data.materials || []);
    currentWorkTypes = (data.bom?.work_types || data.work_types || []);
  } catch {
    availableMaterials = [];
    currentWorkTypes = [];
  }

  // Cargar artesanos (suppliers con tipo artisan)
  let artisans = [];
  try {
    const data = await api('/suppliers');
    artisans = Object.values(data.suppliers || {}).filter(s => s.active !== false);
  } catch {
    artisans = [];
  }

  // Fases del routing
  const phases = (product.production_routing || []).map((step, idx) => ({
    id: step.step_id || (idx + 1),
    name: step.name || `Fase ${idx + 1}`
  }));

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  function renderWorkTypeRow(wt, index) {
    const materialCheckboxes = availableMaterials.map(mat => {
      const checked = (wt.consumes_materials || []).includes(mat.item_id) ? 'checked' : '';
      return `
        <label style="font-size:0.8rem;display:flex;align-items:center;gap:0.3rem;cursor:pointer;margin-right:0.8rem;">
          <input type="checkbox" class="bom-wt-mat" value="${escapeHtml(mat.item_id)}" ${checked} style="accent-color:#3A322E;">
          <span>${escapeHtml(mat.item_id)}</span>
        </label>`;
    }).join('');

    const artisanOptions = artisans.map(a => {
      const selected = a.id === wt.artisan_default_id ? 'selected' : '';
      return `<option value="${escapeHtml(a.id)}" ${selected}>${escapeHtml(a.name)}</option>`;
    }).join('');

    const phaseOptions = phases.map(p => {
      const selected = p.id === wt.phase_ref ? 'selected' : '';
      return `<option value="${p.id}" ${selected}>${escapeHtml(p.name)}</option>`;
    }).join('');

    return `
      <div class="bom-worktype-row" data-index="${index}" style="border:1px solid var(--border);border-radius:4px;padding:0.8rem;margin-bottom:0.5rem;background:#fff;">
        <div style="display:flex;gap:0.5rem;margin-bottom:0.5rem;">
          <div style="flex:2;">
            <label style="font-size:0.75rem;color:#666;">Nombre del trabajo *</label>
            <input type="text" class="bom-wt-name" value="${escapeHtml(wt.name || '')}" placeholder="ej: Cortar bajo" style="width:100%;padding:0.4rem;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:0.85rem;">
          </div>
          <button class="btn btn-sm btn-danger bom-wt-remove" style="padding:0.3rem 0.5rem;font-size:0.75rem;background:#c62828;color:#fff;border:none;border-radius:4px;cursor:pointer;" title="Eliminar">🗑️</button>
        </div>

        <div style="display:flex;gap:0.5rem;margin-bottom:0.5rem;">
          <div style="flex:1;">
            <label style="font-size:0.75rem;color:#666;">Artesano por defecto</label>
            <select class="bom-wt-artisan" style="width:100%;padding:0.4rem;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:0.85rem;">
              <option value="">— Sin asignar —</option>
              ${artisanOptions}
            </select>
          </div>
          <div style="flex:1;">
            <label style="font-size:0.75rem;color:#666;">Fase vinculada</label>
            <select class="bom-wt-phase" style="width:100%;padding:0.4rem;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:0.85rem;">
              <option value="">— Sin fase —</option>
              ${phaseOptions}
            </select>
          </div>
        </div>

        <div style="margin-bottom:0.5rem;">
          <label style="font-size:0.75rem;color:#666;display:block;margin-bottom:0.3rem;">Materiales que consume este trabajo</label>
          <div style="display:flex;flex-wrap:wrap;gap:0.3rem;">
            ${materialCheckboxes || '<span style="color:#888;font-size:0.8rem;">Primero añade materiales en el BOM.</span>'}
          </div>
        </div>

        <div>
          <input type="text" class="bom-wt-notes" placeholder="Notas (opcional)" value="${escapeHtml(wt.notes || '')}" style="width:100%;padding:0.4rem;border:1px solid var(--border);border-radius:4px;font-family:inherit;font-size:0.85rem;">
        </div>
      </div>`;
  }

  overlay.innerHTML = `
    <div class="modal" style="max-width:640px;background:#F2F1ED;max-height:90vh;overflow-y:auto;">
      <p class="modal-title" style="color:#3A322E;">🔧 Trabajos del BOM — ${escapeHtml(product.name)}</p>
      <p style="font-size:0.85rem;color:#888;margin:-0.5rem 0 1rem;">
        Define los trabajos que se hacen en este producto, qué materiales consume cada uno y quién los realiza.
      </p>

      <div id="bom-worktypes-list">
        ${currentWorkTypes.length > 0 ? currentWorkTypes.map((wt, i) => renderWorkTypeRow(wt, i)).join('') : '<p id="bom-wt-empty" style="color:#888;font-size:0.9rem;text-align:center;padding:1rem;">Sin trabajos. Añade uno.</p>'}
      </div>

      <div style="margin:1rem 0;">
        <button class="btn btn-secondary" id="bom-add-worktype" style="width:100%;">+ Añadir trabajo</button>
      </div>

      <div class="modal-actions">
        <button class="btn btn-secondary" data-action="cancel">Cancelar</button>
        <button class="btn btn-primary" data-action="save" style="background:#3A322E;">💾 Guardar BOM</button>
      </div>
    </div>`;

  document.body.appendChild(overlay);

  const listContainer = overlay.querySelector('#bom-worktypes-list');

  function bindRemoveButtons() {
    overlay.querySelectorAll('.bom-wt-remove').forEach(btn => {
      btn.onclick = () => {
        btn.closest('.bom-worktype-row').remove();
        if (overlay.querySelectorAll('.bom-worktype-row').length === 0) {
          listContainer.innerHTML = '<p id="bom-wt-empty" style="color:#888;font-size:0.9rem;text-align:center;padding:1rem;">Sin trabajos. Añade uno.</p>';
        }
      };
    });
  }

  overlay.querySelector('#bom-add-worktype').addEventListener('click', () => {
    const emptyMsg = overlay.querySelector('#bom-wt-empty');
    if (emptyMsg) emptyMsg.remove();
    const idx = overlay.querySelectorAll('.bom-worktype-row').length;
    const div = document.createElement('div');
    div.innerHTML = renderWorkTypeRow({ name: '', artisan_default_id: '', consumes_materials: [], phase_ref: '', notes: '' }, idx);
    listContainer.appendChild(div.firstElementChild);
    bindRemoveButtons();
  });

  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());

  overlay.querySelector('[data-action="save"]').addEventListener('click', async () => {
    const rows = overlay.querySelectorAll('.bom-worktype-row');
    const work_types = [];
    for (const row of rows) {
      const name = row.querySelector('.bom-wt-name').value.trim();
      const artisan_default_id = row.querySelector('.bom-wt-artisan').value || null;
      const phase_ref = row.querySelector('.bom-wt-phase').value || null;
      const notes = row.querySelector('.bom-wt-notes').value.trim();
      const consumes_materials = Array.from(row.querySelectorAll('.bom-wt-mat:checked')).map(cb => cb.value);

      if (!name) { toast('Todos los trabajos deben tener un nombre.', 'error'); return; }

      work_types.push({
        id: `wt_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        name,
        artisan_default_id,
        consumes_materials,
        phase_ref,
        notes: notes || null
      });
    }

    try {
      // Cargar BOM actual para preservar components y materials
      let existingBom = { components: [], materials: [] };
      try {
        const data = await apiAdmin(`/products/${productId}/bom`);
        existingBom.components = data.components || data.bom?.components || [];
        existingBom.materials = data.materials || data.bom?.materials || [];
      } catch {}

      await apiAdmin(`/products/${productId}/bom`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          components: existingBom.components,
          materials: existingBom.materials,
          work_types,
          routing: product.production_routing || []
        })
      });
      toast('Trabajos del BOM guardados correctamente.', 'success');
      overlay.remove();
      if (refreshContent) await refreshContent(root);
    } catch (err) {
      toast(err.message || 'Error guardando BOM', 'error');
    }
  });

  bindRemoveButtons();
}
