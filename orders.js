import { fmtDateTime, statusBadge } from '/js/utils.js';

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
  render(document.getElementById('tab-root'));
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
  render(document.getElementById('tab-root'));
}

async function loadDetail(orderId) {
  state.detailLoading = true;
  state.detailError = null;
  state.selectedId = String(orderId);
  render(document.getElementById('tab-root'));
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
  render(document.getElementById('tab-root'));
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

  return html;
}

function render(root) {
  if (!root) return;
  let html = '<header class="tab-header">' +
    '<h1>Orders</h1>' +
    '<p class="tab-subtitle">' + state.orders.length + ' orders loaded.</p>' +
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

  const fulfillBtn = root.querySelector('[data-action="fulfill"]');
  if (fulfillBtn) {
    fulfillBtn.addEventListener('click', function() {
      if (state.selectedId) fulfillOrder(state.selectedId);
    });
  }
}

export function render(root, subPath) {
  loadOrders();
}
