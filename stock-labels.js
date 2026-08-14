/**
 * POTISSE Stock/Products UI Labels (español)
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

  // Estados batch pipeline (backend key → label ES)
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
  threshold: 'Umbral',
  min_threshold: 'Umbral mínimo',
  critical_threshold: 'Umbral crítico',
  reorder_point: 'Punto de reposición',
  standard_lead_time: 'Plazo típico entrega',
  buffer_days: 'Días de margen',
  cost_accumulated: 'Coste acumulado',
  standard_supplier: 'Proveedor habitual',
  standard_flow: 'Flujo estándar',

  // Actions comunes
  create: 'Crear',
  edit: 'Editar',
  delete: 'Eliminar',
  save: 'Guardar',
  cancel: 'Cancelar',
  confirm: 'Confirmar',
  refresh: 'Actualizar',
  search: 'Buscar',
  filter: 'Filtrar',

  // Empty states
  empty_no_items: 'Sin artículos creados aún.',
  empty_no_suppliers: 'Sin proveedores registrados aún.',
  empty_no_batches: 'Sin lotes en curso.',
  empty_healthy: 'Todo en orden.',
  // Estados stock item
  item_status: {
    healthy: 'Correcto',
    low: 'Bajo',
    critical: 'Crítico',
    out_of_stock: 'Sin stock'
  },

  // Categorías item
  item_category: {
    packaging: 'Packaging',
    garment: 'Prenda',
    raw_material: 'Materia prima',
    finished_good: 'Producto terminado',
    hardware: 'Hardware / NFC',
    label: 'Etiqueta'
  },

  // Unidades de medida
  unit_of_measure: {
    units: 'unidades',
    meters: 'metros',
    kilograms: 'kg',
    liters: 'litros'
  },

  // Origin type
  origin_type: {
    local: 'Local (España)',
    eu: 'Unión Europea',
    extra_eu: 'Fuera UE'
  },

  // Campos item
  fields: {
    id: 'ID interno',
    sku: 'SKU',
    name: 'Nombre',
    category: 'Categoría',
    unit_of_measure: 'Unidad',
    min_threshold: 'Umbral mínimo',
    critical_threshold: 'Umbral crítico',
    current_stock: 'Stock actual',
    standard_supplier_id: 'Proveedor habitual',
    standard_lead_time_days: 'Plazo entrega (días)',
    buffer_days: 'Días de margen',
    origin_type: 'Origen',
    is_shopify_master: 'Master en Shopify',
    shopify_variant_id: 'Variant ID Shopify',
    has_bom: 'Tiene BOM',
    active: 'Activo'
  },

  // BOM
  bom: {
    title: 'BOM — Componentes',
    empty: 'Sin componentes definidos.',
    add_component: 'Añadir componente',
    quantity: 'Cantidad',
    optional: 'Opcional',
    standard_flow: 'Flujo estándar',
    add_step: 'Añadir paso'
  },

  // POs
  po: {
    title: 'Pedidos de compra',
    create: 'Nuevo pedido',
    empty: 'Sin pedidos registrados.',
    total: 'Total',
    lines: 'Líneas',
    quantity: 'Cantidad',
    unit_price: 'Precio unidad',
    subtotal: 'Subtotal',
    expected_delivery: 'Llegada esperada',
    actual_delivery: 'Llegada real',
    receive: 'Recibir'
  },

  // Empty states catálogo
  empty_no_items: 'Sin artículos en el catálogo. Empieza creando el primero.',
  empty_no_pos: 'Sin pedidos registrados. Crea uno desde un item o proveedor.',

};

/**
 * Helper: traduce una key con fallback al key original si no existe.
 * Uso: label('batch_status.with_artisan') → 'Con artesano'
 *      label('unknown_key') → 'unknown_key'
 */
export function label(key) {
  const parts = key.split('.');
  let value = LABELS;
  for (const part of parts) {
    if (value && typeof value === 'object' && part in value) {
      value = value[part];
    } else {
      return key; // fallback
    }
  }
  return typeof value === 'string' ? value : key;
}