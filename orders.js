import { fmtDateTime, escapeHtml } from '/js/utils.js';
import { openNFCProgrammingWizard, checkRecoverableSession } from '/js/lib/nfc-programming-wizard.js';

let state = {
  orders: [],
  loading: false,
  error: null,
  selectedId: null,
  detail: null,
  detailLoading: false,
  detailError: null,
};

function formatCustomerName(customer) {
  if (!customer) return 'Guest';
  return ((customer.first_name || '') + ' ' + (customer.last_name || '')).trim() || customer.email || 'Guest';
}

function formatPrice(order) {
  return order.total_price ? order.total_price + ' ' + (order.currency || '') : '-';
}

function fulfillmentBadge(status) {
  if (status === 'fulfilled') return '<span class="badge badge-success">Fulfilled</span>';
  if (status === 'partial') return '<span class="badge badge-warning">Partial</span>';
  if (status === 'restocked') return '<span class="badge badge-info">Restocked</span>';
  return '<span class="badge badge-secondary">Unfulfilled</span>';
}

function financialBadge(status) {
  if (status === 'paid') return '<span class="badge badge-success">Paid</span>';
  if (status === 'pending') return '<span class="badge badge-warning">Pending</span>';
  if (status === 'refunded') return '<span class="badge badge-info">Refunded</span>';
  if (status === 'partially_refunded') return '<span class="badge badge-warning">Partially refunded</span>';
  return '<span class="badge badge-secondary">' + (status || 'Unknown') + '</span>';
}

async function loadOrders() {
  state.loading = true;
  state.error = null;
  renderContent(document.getElementById('tab-root'));
  try {
    const res = await fetch('/api/proxy/admin/orders/list');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    state.orders = data.orders || [];
    if (state.orders.length > 0 && !state.selectedId) {
      state.selectedId = String(state.orders[0].id);
      loadDetail(state.selectedId);
    }
  } catch (err) {
    state.error = err.message;
  }
  state.loading = false;
  renderContent(document.getElementById('tab-root'));
}

async function loadDetail(orderId) {
  state.detailLoading = true;
  state.detailError = null;
  state.selectedId = String(orderId);
  renderContent(document.getElementById('tab-root'));
  try {
    const res = await fetch('/api/proxy/admin/orders/' + orderId);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    state.detail = data.order;
  } catch (err) {
    state.detailError = err.message;
    state.detail = null;
  }
  state.detailLoading = false;
  renderContent(document.getElementById('tab-root'));
}

async function fulfillOrder(orderId) {
  if (!confirm('Create fulfillment for this order?')) return;
  try {
    const res = await fetch('/api/proxy/admin/orders/' + orderId + '/fulfill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'HTTP ' + res.status);
    }
    const data = await res.json();
    alert('Fulfillment created: ' + (data.fulfillment && data.fulfillment.name ? data.fulfillment.name : 'OK'));
    loadDetail(orderId);
  } catch (err) {
    alert('Fulfill failed: ' + err.message);
  }
}

/* ═══════════════════════════════════════════════════════════════════ */
/*  CHECKLIST COMPONENT (Deliverable 1)                              */
/* ═══════════════════════════════════════════════════════════════════ */

const CHECKLIST_STEPS = [
  { key: 'verify_data', label: 'Verificar datos del cliente' },
  { key: 'email_customer_if_doubts', label: 'Contactar si hay dudas' },
  { key: 'wait_reply', label: 'Esperar respuesta del cliente' },
  { key: 'resolve_doubt', label: 'Resolver duda' },
  { key: 'customer_data_kv', label: 'Sincronizar datos en KV' },
  { key: 'garment_confirmed', label: 'Inspeccionar y confirmar la prenda' },
  { key: 'nfc_programmed', label: 'Programar la tarjeta The Club' },
  { key: 'nfc_linked', label: 'Vincular la tarjeta al pedido' },
  { key: 'gls_label_printed', label: 'Imprimir etiqueta GLS' },
  { key: 'packaging_prepared', label: 'Preparar envoltorio editorial' },
  { key: 'shopify_marked_sent', label: 'Marcar enviado en Shopify' },
  { key: 'final_timestamp', label: 'Timestamp final del pedido' }
];

function renderChecklist(order) {
  const checklist = order.checklist || {};
  let completedCount = 0;
  let firstPendingIndex = -1;

  for (let i = 0; i < CHECKLIST_STEPS.length; i++) {
    const step = CHECKLIST_STEPS[i];
    const data = checklist[step.key] || {};
    if (data.completed) completedCount++;
    else if (firstPendingIndex === -1) firstPendingIndex = i;
  }

  let html = '<div class="checklist-section" style="margin-top:24px;">';
  html += '<div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">';
  html += '<div class="section-heading" style="margin:0;">Checklist del pedido</div>';
  html += '<div style="font-size:12px; color:rgba(58,50,46,0.55); font-weight:500;">' + completedCount + '/12 completado</div>';
  html += '</div>';
  html += '<div class="checklist" style="gap:0; border:1px solid rgba(58,50,46,0.1); border-radius:8px; overflow:hidden;">';

  for (let i = 0; i < CHECKLIST_STEPS.length; i++) {
    const step = CHECKLIST_STEPS[i];
    const data = checklist[step.key] || {};
    const isCompleted = !!data.completed;
    const isPending = i === firstPendingIndex;
    const isFuture = i > firstPendingIndex && firstPendingIndex !== -1;
    const isBlocked = !isCompleted && !isPending;

    const circleColor = isCompleted ? '#3A322E' : (isPending ? '#E8C48A' : 'rgba(58,50,46,0.15)');
    const circleText = isCompleted ? '✓' : String(i + 1);
    const circleTextColor = isCompleted ? '#F2F1ED' : (isPending ? '#3A322E' : 'rgba(58,50,46,0.35)');

    let rowStyle = 'display:flex; align-items:center; gap:12px; padding:10px 14px; border-bottom:1px solid rgba(58,50,46,0.06);';
    if (isFuture) rowStyle += ' opacity:0.4;';
    if (isPending) rowStyle += ' background:rgba(232,196,138,0.08);';

    html += '<div style="' + rowStyle + '">';
    html += '<div style="width:26px; height:26px; border-radius:50%; background:' + circleColor + '; color:' + circleTextColor + '; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:600; flex-shrink:0;">' + circleText + '</div>';
    html += '<div style="flex:1;">';
    html += '<div style="font-size:14px; color:' + (isFuture ? 'rgba(58,50,46,0.45)' : '#3A322E') + '; font-weight:' + (isPending ? '600' : '400') + ';">' + escapeHtml(step.label) + '</div>';
    if (isCompleted && data.completed_at) {
      html += '<div style="font-size:11px; color:rgba(58,50,46,0.45); margin-top:2px;">' + fmtDateTime(data.completed_at) + (data.completed_by ? ' · ' + escapeHtml(data.completed_by) : '') + '</div>';
    }
    html += '</div>';

    if (step.key === 'nfc_programmed' && isPending) {
      const recover = checkRecoverableSession(order.id);
      if (recover) {
        html += '<button class="btn btn-sm" data-action="resume-nfc" style="background:#3A322E; color:#F2F1ED; border:none; padding:6px 14px; border-radius:6px; font-size:12px; cursor:pointer; white-space:nowrap;">Retomar sesión</button>';
      } else {
        html += '<button class="btn btn-sm" data-action="program-nfc" style="background:#3A322E; color:#F2F1ED; border:none; padding:6px 14px; border-radius:6px; font-size:12px; cursor:pointer; white-space:nowrap;">PROGRAMAR TARJETA THE CLUB</button>';
      }
    }
    if (step.key === 'nfc_programmed' && isCompleted && data.uid) {
      html += '<a href="#/nfc-cards" style="font-size:11px; color:#3A322E; text-decoration:underline; font-family:"IBM Plex Mono",monospace;">' + escapeHtml(data.uid) + '</a>';
    }

    if (step.key === 'garment_confirmed' && isPending) {
      html += '<button class="btn btn-sm btn-secondary" data-action="mark-defect" style="font-size:11px; padding:4px 10px;">Marcar defecto</button>';
    }

    html += '</div>';
  }

  html += '</div></div>';
  return html;
}

function handleProgramNFC(order) {
  const customerId = order.customer && order.customer.id ? String(order.customer.id) : '';
  openNFCProgrammingWizard({
    mode: 'production',
    order_id: String(order.id),
    customer_id: customerId,
    onComplete: ({ uid, mode, sessionId }) => {
      loadDetail(order.id);
    },
    onCancel: ({ stage }) => {
      console.log('[NFC Wizard] Cancelado en etapa', stage);
    }
  });
}

function handleResumeNFC(order) {
  handleProgramNFC(order);
}

/* ═══════════════════════════════════════════════════════════════════ */

function renderListItem(order) {
  const isActive = String(order.id) === state.selectedId;
  const customerName = formatCustomerName(order.customer);
  const name = order.name || ('#' + order.order_number);
  return '<div class="split-list-item' + (isActive ? ' active' : '') + '" data-order-id="' + order.id + '">' +
    '<div class="col-mono">' + name + '</div>' +
    '<div>' + customerName + '</div>' +
    '<div style="margin-top: 4px;">' +
      financialBadge(order.financial_status) +
      fulfillmentBadge(order.fulfillment_status) +
      '<span class="card-meta" style="margin-left: 8px;">' + formatPrice(order) + '</span>' +
    '</div>' +
  '</div>';
}

function renderLineItem(item) {
  const title = item.title || 'Product';
  const sku = item.sku || '-';
  return '<div class="checklist-item">' +
    '<div class="checklist-checkbox"></div>' +
    '<div class="checklist-label">' + title + ' x ' + item.quantity + '</div>' +
    '<div class="checklist-timestamp">' + sku + '</div>' +
  '</div>';
}

function renderDetail() {
  if (state.detailLoading) {
    return '<div class="placeholder">Loading order...</div>';
  }
  if (state.detailError) {
    return '<div class="placeholder" style="color:var(--danger)">Error: ' + state.detailError + '</div>';
  }
  if (!state.detail) {
    return '<div class="placeholder">Select an order to view details.</div>';
  }

  const o = state.detail;
  const customerName = formatCustomerName(o.customer);
  const email = (o.customer && o.customer.email) ? o.customer.email : '-';
  const orderName = o.name || ('#' + o.order_number);
  const canFulfill = o.fulfillment_status !== 'fulfilled' && o.fulfillment_status !== 'restocked';

  let html = '<div class="card-header">' +
    '<div class="card-title">Order ' + orderName + '</div>' +
    financialBadge(o.financial_status) +
  '</div>' +
  '<p class="card-meta">' + customerName + ' - ' + email + ' - created ' + fmtDateTime(o.created_at) + '</p>' +
  '<div class="section-heading">Line items</div>' +
  '<div class="checklist">';

  if (o.line_items && o.line_items.length) {
    html += o.line_items.map(renderLineItem).join('');
  } else {
    html += '<div class="placeholder">No line items</div>';
  }

  html += '</div>' +
  '<div class="section-heading">Fulfillment</div>' +
  '<div style="margin-bottom: 16px;">' +
    fulfillmentBadge(o.fulfillment_status);

  if (canFulfill) {
    html += '<button type="button" class="btn btn-primary" data-action="fulfill" style="margin-left: 12px;">Fulfill order</button>';
  }

  html += '</div>';

  if (o.fulfillments && o.fulfillments.length) {
    html += '<div class="checklist">' +
      o.fulfillments.map(function(f) {
        const company = f.tracking_company || 'Fulfillment';
        const number = f.tracking_number || '';
        return '<div class="checklist-item completed">' +
          '<div class="checklist-checkbox">OK</div>' +
          '<div class="checklist-label">' + company + ' ' + number + '</div>' +
          '<div class="checklist-timestamp">' + fmtDateTime(f.created_at) + '</div>' +
        '</div>';
      }).join('') +
    '</div>';
  }

  html += renderChecklist(o);

  return html;
}

async function loadSyntheticOrder(orderId) {
  state.detailLoading = true;
  state.detailError = null;
  state.selectedId = orderId;
  renderContent(document.getElementById('tab-root'));
  try {
    const res = await fetch('/api/proxy/admin/nfc/debug-key', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: 'order_' + orderId + '.checklist' })
    });
    if (!res.ok) throw new Error('Checklist no encontrado');
    const data = await res.json();
    const checklist = data.value || {};
    state.detail = {
      id: orderId, name: orderId, order_number: orderId.replace('TEST-NFC-', ''),
      customer: { id: '9854965252438', first_name: 'JAVIER', last_name: 'SHOPIFY', email: 'motuxx@hotmail.com' },
      financial_status: 'paid', fulfillment_status: 'unfulfilled',
      created_at: new Date().toISOString(), total_price: '0.00', currency: 'EUR',
      line_items: [{ title: 'Tarjeta The Club (TEST)', quantity: 1, sku: 'NFC-TEST' }],
      checklist: checklist
    };
  } catch (err) {
    state.detailError = 'Order sintetico no encontrado: ' + err.message;
    state.detail = null;
  }
  state.detailLoading = false;
  renderContent(document.getElementById('tab-root'));
}

function renderContent(root) {
  if (!root) return;
  let html = '<header class="tab-header">' +
    '<h1>Orders</h1>' +
    '<p class="tab-subtitle">' + state.orders.length + ' orders loaded.</p>' +
    '<div style="margin-top:8px;">' +
      '<input type="text" id="synthetic-order-id" placeholder="Order ID sintetico (TEST-NFC-...)" style="padding:6px 10px;border:1px solid rgba(58,50,46,0.2);border-radius:4px;font-size:13px;width:220px;">' +
      '<button class="btn btn-sm" id="load-synthetic-btn" style="margin-left:6px;background:#3A322E;color:#F2F1ED;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;">Cargar</button>' +
    '</div>' +
  '</header>' +
  '<div class="tab-content">' +
    '<div class="split-layout">' +
      '<div class="split-list">' +
        '<div class="section-heading" style="margin-top:0;">Orders</div>';

  if (state.loading) {
    html += '<div class="placeholder">Loading...</div>';
  }
  if (state.error) {
    html += '<div class="placeholder" style="color:var(--danger)">' + state.error + '</div>';
  }
  if (!state.loading && !state.error) {
    html += state.orders.map(renderListItem).join('');
  }

  html += '</div>' +
      '<div class="split-detail">' + renderDetail() + '</div>' +
    '</div>' +
  '</div>';

  root.innerHTML = html;

  root.querySelectorAll('.split-list-item').forEach(function(el) {
    el.addEventListener('click', function() {
      const id = el.dataset.orderId;
      if (id) loadDetail(id);
    });
  });
  const syntheticBtn = root.querySelector('#load-synthetic-btn');
  const syntheticInput = root.querySelector('#synthetic-order-id');
  if (syntheticBtn && syntheticInput) {
    syntheticBtn.addEventListener('click', function() {
      const id = syntheticInput.value.trim();
      if (id) loadSyntheticOrder(id);
    });
    syntheticInput.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        const id = syntheticInput.value.trim();
        if (id) loadSyntheticOrder(id);
      }
    });
  }

  const fulfillBtn = root.querySelector('[data-action="fulfill"]');
  if (fulfillBtn) {
    fulfillBtn.addEventListener('click', function() {
      if (state.selectedId) fulfillOrder(state.selectedId);
    });
  }

  const programBtn = root.querySelector('[data-action="program-nfc"]');
  if (programBtn) {
    programBtn.addEventListener('click', () => handleProgramNFC(state.detail));
  }
  const resumeBtn = root.querySelector('[data-action="resume-nfc"]');
  if (resumeBtn) {
    resumeBtn.addEventListener('click', () => handleResumeNFC(state.detail));
  }
  const defectBtn = root.querySelector('[data-action="mark-defect"]');
  if (defectBtn) {
    defectBtn.addEventListener('click', () => {
      alert('Flow de incidencia — redirige a tab Incidences (ya existente)');
    });
  }
}

export function render(root, subPath) {
  loadOrders();
}
