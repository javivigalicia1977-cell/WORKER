/**
 * POTISSE Stock/Products UI Labels v2.4 (español) — C.5-B.5
 * Backend usa keys inglesas (item, supplier, batch, PO...). Este diccionario
 * traduce lo visible al usuario. Regla: backend inglés, frontend UI español.
 */

export const LABELS = {
  // Entidades
  item: 'Artículo',
  items: 'Artículos',
  supplier: 'Proveedor',
  suppliers: 'Proveedores',
  artisan: 'Artesano',
  artisans: 'Artesanos',
  batch: 'Lote',
  batches: 'Lotes',

  // Abreviaturas técnicas
  BOM: 'Componentes',
  PO: 'Pedido',
  POs: 'Pedidos',
  QC: 'Control',
  SKU: 'SKU',
  Stock: 'Stock',
  ETA: 'Llegada estimada',
  SLA: 'Plazo',

  // Estados batch pipeline (backend key -> label ES)
  batch_status: {
    to_order: 'Por pedir',
    ordered: 'Pedido',
    in_house: 'En casa',
    with_artisan: 'Con artesano',
    qc_pending: 'Control pendiente',
    stock_ready: 'En stock',
    discarded: 'Descartado'
  },

  // Estados PO
  po_status: {
    draft: 'Borrador',
    sent: 'Enviado',
    confirmed: 'Confirmado',
    shipped: 'En tránsito',
    received: 'Recibido',
    cancelled: 'Cancelado'
  },

  // Niveles urgency restock
  urgency: {
    out_of_stock: 'Sin stock',
    order_now: 'Pedir YA',
    order_soon: 'Pedir pronto',
    plan_to_order: 'Planificar pedido',
    healthy: 'Correcto'
  },

  // Tipos de activity en batch
  activity_type: {
    note: 'Nota',
    transition: 'Cambio de estado',
    email_sent: 'Email enviado',
    email_received: 'Email recibido',
    call_log: 'Llamada o mensaje',
    photo_attached: 'Foto adjunta',
    cost_logged: 'Coste anotado',
    qc_result: 'Resultado control',
    alert: 'Alerta'
  },

  // Medios de comunicacion (call_log)
  call_medium: {
    call: 'Llamada telefónica',
    whatsapp: 'WhatsApp',
    sms: 'SMS',
    visit: 'Visita en persona'
  },

  // Tipos supplier
  supplier_type: {
    supplier: 'Proveedor',
    artisan_external: 'Artesano externo',
    artisan_internal: 'Artesano interno',
    both: 'Proveedor y artesano'
  },

  // Origen (afecta buffer restock)
  origin_type: {
    local: 'Local (España)',
    eu: 'Unión Europea',
    extra_eu: 'Fuera de UE'
  },

  // Umbrales stock
  threshold: {
    critical: 'Crítico',
    low: 'Bajo',
    normal: 'Normal',
    high: 'Alto'
  },

  // Empty states
  empty_no_batches: 'No hay lotes registrados.',
  empty_filter_no_results: 'Ningún lote coincide con el filtro.',
  empty_no_activities: 'Sin actividad registrada.',

  // QC labels
  qc: {
    checklist_default: [
      'Hilos sueltos',
      'Manchas',
      'Roturas',
      'Bordado',
      'Talla',
      'Etiqueta',
      'Dimensiones',
      'Acabado'
    ],
    pass: 'Aprobado',
    fail: 'Rechazado',
    approved: 'Aprobadas',
    rejected: 'Rechazadas',
    add_custom: 'Añadir punto'
  },

  // Guardrail
  guardrail: {
    recent_comm_title: 'Comunicación reciente',
    recent_comm_body: 'Ya existe una comunicación con este contacto en las últimas 24h.',
    force_confirm: 'Forzar registro',
    force_cancel: 'Cancelar'
  },

  // ═════════════════════════════════════════════════════════════════
  // NUEVO C.5-B.5 — Overview
  // ═════════════════════════════════════════════════════════════════
  overview: {
    title: 'Overview',
    subtitle: 'Vista global del sistema de stock POTISSE',
    restock_urgent_title: 'Restock urgente',
    suggested_actions_title: 'Acciones sugeridas hoy',
    pipeline_snapshot_title: 'Estado del pipeline',
    recent_pos_title: 'Pedidos recientes',
    view_all: 'Ver todos',
    create_grouped_po: 'Crear pedido agrupado',
    no_urgent_today: 'Nada urgente hoy. ✓',
    no_batches: 'Sin lotes en curso.',
    no_pos_yet: 'Sin pedidos aún.',
    new_po: 'Nuevo pedido',
    alerts: {
      urgent_items: 'Ítems urgentes',
      inactive_batches: 'Lotes inactivos +48h',
      qc_pending: 'QC pendientes',
      pos_waiting: 'POs esperando confirmación'
    }
  },

  // ═════════════════════════════════════════════════════════════════
  // NUEVO C.5-B.5 — PO Actions
  // ═════════════════════════════════════════════════════════════════
  po_actions: {
    save_draft: 'Guardar como borrador',
    save_and_send: 'Guardar y enviar',
    edit: 'Editar',
    mark_sent: 'Enviar',
    mark_confirmed: 'Marcar confirmado',
    mark_shipped: 'Marcar en tránsito',
    receive: 'Recibir',
    cancel: 'Cancelar pedido'
  },

  // ═════════════════════════════════════════════════════════════════
  // NUEVO C.5-B.5 — PO Receive Modal
  // ═════════════════════════════════════════════════════════════════
  po_receive_modal: {
    title: 'Recibir pedido',
    info: 'Se crearán lotes automáticos con estado "En casa" vinculados a este pedido.',
    received_label: 'Recibido',
    delivery_date_label: 'Fecha llegada real'
  },

  // ═════════════════════════════════════════════════════════════════
  // NUEVO C.5-B.5 — Genealogy
  // ═════════════════════════════════════════════════════════════════
  genealogy: {
    title: 'Árbol de trazabilidad',
    ancestors_title: 'Ancestros (origen)',
    descendants_title: 'Descendientes',
    current_marker: '← LOTE ACTUAL',
    no_ancestors: 'Origen: sin lotes padre (creado desde 0 o migración)',
    no_descendants: 'Sin derivados aún',
    view_tree: 'Ver árbol de trazabilidad'
  }

  // UI Actions (C.5-B.5 fix)
  refresh: 'Actualizar',
  delete: 'Eliminar',
  empty_no_items: 'No hay artículos registrados.',
};

// Helper: acceso por path tipo "batch_status.ordered"
export function label(path) {
  const parts = path.split('.');
  let current = LABELS;
  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) {
      current = current[part];
    } else {
      return null;
    }
  }
  return current;
}

// ═════════════════════════════════════════════════════════════════
// FIX C.5-B.5: Expose globally for dynamic modules (overview-view.js)
// ═════════════════════════════════════════════════════════════════
if (typeof window !== 'undefined') {
  window.LABELS = LABELS;
  window.label = label;
}
