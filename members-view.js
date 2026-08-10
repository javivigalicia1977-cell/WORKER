// ═══════════════════════════════════════════════════════════════════════
// POTISSE — members-view.js  v6.9.5  (PII Lockdown Real)
// Shopify es fuente de verdad PII | Panel solo edita notes/language/tags
// Generado: 2026-08-10
// ═══════════════════════════════════════════════════════════════════════

import { api } from '/js/api.js?v=9';
import { fmtDate, fmtDateTime, timeAgo, escapeHtml } from '/js/utils.js';
import { confirmModal, tripleConfirmModal, toast } from '/js/ui.js';

// ═══════════════════════════════════════════════════════════════════════
// CONFIGURACION GOOGLE PLACES
// ═══════════════════════════════════════════════════════════════════════
const GOOGLE_PLACES_API_KEY = 'AIzaSyDMozXrtktH8Q3w4V3ENlltER4R2FjSNoI';

function loadGooglePlacesScript() {
  if (window.google && window.google.maps && window.google.maps.places) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    if (document.querySelector('script[data-google-places]')) {
      const check = setInterval(() => {
        if (window.google && window.google.maps && window.google.maps.places) {
          clearInterval(check);
          resolve();
        }
      }, 100);
      setTimeout(() => { clearInterval(check); reject(new Error('Timeout')); }, 10000);
      return;
    }
    if (GOOGLE_PLACES_API_KEY === 'TU_API_KEY_AQUI') {
      console.warn('Google Places: API key no configurada');
      reject(new Error('API key not configured'));
      return;
    }
    const script = document.createElement('script');
    script.src = `https://maps.googleapis.com/maps/api/js?key=${GOOGLE_PLACES_API_KEY}&libraries=places`;
    script.async = true;
    script.defer = true;
    script.setAttribute('data-google-places', 'true');
    script.onload = resolve;
    script.onerror = () => reject(new Error('Failed to load Google Places'));
    document.head.appendChild(script);
  });
}

function initAddressAutocomplete(inputEl, onComponents) {
  loadGooglePlacesScript().then(() => {
    const autocomplete = new google.maps.places.Autocomplete(inputEl, {
      types: ['address'],
      fields: ['formatted_address', 'address_components']
    });
    autocomplete.addListener('place_changed', () => {
      const place = autocomplete.getPlace();
      if (place.formatted_address) {
        inputEl.value = place.formatted_address;
        const components = {};
        if (place.address_components) {
          for (const comp of place.address_components) {
            if (comp.types.includes('street_number')) components.street_number = comp.long_name;
            if (comp.types.includes('route')) components.route = comp.long_name;
            if (comp.types.includes('locality')) {
              components.city = comp.long_name;
            } else if (!components.city && comp.types.includes('postal_town')) {
              components.city = comp.long_name;
            } else if (!components.city && comp.types.includes('sublocality')) {
              components.city = comp.long_name;
            }
            if (comp.types.includes('administrative_area_level_2')) {
              components.province = comp.long_name;
            } else if (!components.province && comp.types.includes('administrative_area_level_1')) {
              components.province = comp.long_name;
            }
            if (comp.types.includes('postal_code')) components.postal_code = comp.long_name;
            if (comp.types.includes('country')) components.country = comp.short_name;
          }
        }
        if (components.route) {
          components.address_line1 = components.route;
          if (components.street_number) components.address_line1 += ', ' + components.street_number;
        }
        console.log('[GP] Extracted components:', JSON.stringify(components));
        if (onComponents) onComponents(components);
        setTimeout(() => {
          inputEl.focus();
          inputEl.setSelectionRange(inputEl.value.length, inputEl.value.length);
        }, 10);
      }
    });
  }).catch(err => {
    console.error('Google Places error:', err.message);
  });
}

const EMAIL_TEMPLATES = [
  { value: 'size_color', label: 'Consulta talla o color', category: 'Preventa / Información' },
  { value: 'product_availability', label: 'Disponibilidad producto', category: 'Preventa / Información' },
  { value: 'production_timing', label: 'Timing próxima producción', category: 'Preventa / Información' },
  { value: 'address_check', label: 'Verificar dirección', category: 'Pedido en curso' },
  { value: 'nfc_quantity', label: 'Confirmar cantidad piezas', category: 'Pedido en curso' },
  { value: 'delivery_availability_check', label: 'Delivery availability check', category: 'Pedido en curso' },
  { value: 'delivery_confirmation', label: 'Confirmar entrega correcta', category: 'Entrega' },
  { value: 'delivery_delayed', label: 'Aviso retraso GLS', category: 'Entrega' },
  { value: 'defect_apology', label: 'Disculpa por defecto', category: 'Incidencias' },
  { value: 'return_confirmation', label: 'Confirmación devolución recibida', category: 'Incidencias' },
  { value: 'first_wear_check', label: 'First wear check', category: 'Post-venta emocional' },
  { value: 'wash_reminder', label: 'Wash reminder', category: 'Post-venta emocional' },
  { value: 'silencio_1_courtesy', label: 'Silencio 1 courtesy notification', category: 'Silencios' },
  { value: 'silencio_3_response', label: 'Silencio 3 response editorial', category: 'Silencios' },
  { value: 'custom', label: 'Custom email libre', category: 'Genérico' }
];
const EMAIL_TEMPLATE_DEFAULTS = {
  size_color: {
    subject: 'A quiet question about your size.',
    body: `Hello {first_name},

We received your question about {product_name}.

{custom_body}

Take your time. There is no rush from us.

— POTISSE`
  },
  product_availability: {
    subject: 'About what you were looking for.',
    body: `Hello {first_name},

The piece you asked about — {product_name} — is not always with us. We work in small, permanent batches, and we prefer to make less, well.

{status_line}

If you would like us to remember you when it returns, reply to this message and we will hold your name in our list.

— POTISSE`
  },
  production_timing: {
    subject: 'On the next batch.',
    body: `Hello {first_name},

Thank you for waiting. {product_name} is being prepared in María de Huerva, and will return to us around {estimated_date}.

We do not push the makers. Nor the fabric. It arrives when it is ready.

If anything changes, we will write again.

— POTISSE`
  },
  address_check: {
    subject: 'A moment before we send it.',
    body: `Hello {first_name},

Before we prepare your order for shipping, we would like to confirm your address:

{shipping_address_block}

If everything is correct, no reply is needed. We will proceed within the day.

If anything should change, reply to this message and we will hold the order until you tell us.

— POTISSE`
  },
  nfc_quantity: {
    subject: 'A note on your order.',
    body: `Hello {first_name},

Your order includes {pieces_count} {pieces_word}. Each one will arrive with its own card — small, discreet, holding its own history.

If this does not match what you expected, reply to this message before {cutoff_date} and we will pause the order.

— POTISSE`
  },
  delivery_availability_check: {
    subject: 'Just to be sure it arrives well.',
    body: `Hello {first_name},

Your piece will be with GLS in the coming days, arriving to:

{shipping_address_short}

Will you be there in the next five days to receive it? If not, or if you prefer we hold it until you return, reply to this message and we will pause.

Otherwise, no reply is needed — we will proceed.

— POTISSE`
  },
  delivery_confirmation: {
    subject: 'Did it arrive well?',
    body: `Hello {first_name},

We saw that your piece was marked as delivered on {delivered_date}. We wanted to make sure it reached you — not just the door.

If it did, no reply is needed.

If something is not as it should be — the packaging, the piece, anything — reply to this message. We will listen without hurry.

— POTISSE`
  },
  delivery_delayed: {
    subject: 'A small delay on the way.',
    body: `Hello {first_name},

GLS has reported a delay on your shipment. It has not been lost — only paused somewhere between us and you.

{reason_line}

We will keep watching, and will write again once it moves. If you prefer to hold or change anything, reply to this message.

Thank you for your patience. It is not a light word for us.

— POTISSE`
  },
  defect_apology: {
    subject: 'We noticed something on your piece.',
    body: `Hello {first_name},

During inspection, we found a detail on your {product_name} that does not meet what we expect from a POTISSE piece: {defect_description}.

We would rather tell you now than hope you would not notice.

Your options:

— Wait for a replacement from the next batch. Estimated arrival: {estimated_date}.
— Refund in full, no return needed.

Reply to this message and let us know how you would like to proceed. There is no wrong choice.

— POTISSE`
  },
  return_confirmation: {
    subject: 'Your return has arrived.',
    body: `Hello {first_name},

Your {product_name} arrived back with us on {return_date}. We will inspect it in the coming days and process the refund of {refund_amount} to your original method of payment.

You should see it in your account within {refund_days_estimate}, depending on your bank.

If you would like the piece to return to you in a different size, reply to this message and we will arrange it.

— POTISSE`
  },
  first_wear_check: {
    subject: 'A quiet check-in.',
    body: `─────

LOCATION: 50430 · STATUS: {days_since_delivery} days with you.

A piece takes time to become yours.
The first days are still ceremony.

How does it wear?

If it has already found its place in your rhythm, no reply is needed.
If not — reply. We will listen.

─── POTISSE 2026`
  },
  wash_reminder: {
    subject: 'A gentle reminder.',
    body: `─────

LOCATION: 50430 · STATUS: {washes} washes registered.

Your piece is settling.

If you have washed it recently and forgotten to register it, the door is open — no rush.

Each wash is part of how it becomes yours.

https://potisse.com/pages/side-b

─── POTISSE 2026`
  },
  silencio_1_courtesy: {
    subject: 'A quiet gesture.',
    body: `─────

LOCATION: 50430 · STATUS: Courtesy shipping, activated.

From today, your orders arrive with us covering the transit.

It is a quiet gesture. Nothing to announce, nothing to reciprocate.

Just a way of saying: we notice you.

─── POTISSE 2026`
  },
  silencio_3_response: {
    subject: 'On your piece.',
    body: `─────

LOCATION: 50430 · STATUS: Silencio 3, received.

We received your message about {incident_summary}.

It is not necessary to return the affected piece.

We will resolve this from our side, quietly.

If you wish to write again, the door remains ajar.

─── POT · Fran
─── POTISSE 2026`
  },
  custom: {
    subject: '',
    body: ''
  }
};
const POTISSE_LOGO_URL = 'https://cdn.shopify.com/s/files/1/0914/8196/4886/files/LOGO_POTISSE_VINTO_TINTO_AMARRONADO_1C1816.svg?v=1775985373';
const EDITORIAL_TEMPLATES = ['size_color', 'product_availability', 'production_timing', 'address_check', 'nfc_quantity', 'delivery_availability_check', 'delivery_confirmation', 'delivery_delayed', 'defect_apology', 'return_confirmation', 'custom'];


const LANGUAGE_OPTIONS = [
  { value: 'EN', label: 'EN' },
  { value: 'ES', label: 'ES' },
  { value: '', label: '(None)' }
];

const COUNTRY_OPTIONS = [
  { value: '', label: '(None)' },
  { value: 'ES', label: '🇪🇸 Spain' },
  { value: 'PT', label: '🇵🇹 Portugal' },
  { value: 'FR', label: '🇫🇷 France' },
  { value: 'DE', label: '🇩🇪 Germany' },
  { value: 'IT', label: '🇮🇹 Italy' },
  { value: 'NL', label: '🇳🇱 Netherlands' },
  { value: 'BE', label: '🇧🇪 Belgium' },
  { value: 'AT', label: '🇦🇹 Austria' },
  { value: 'IE', label: '🇮🇪 Ireland' },
  { value: 'DK', label: '🇩🇰 Denmark' },
  { value: 'SE', label: '🇸🇪 Sweden' },
  { value: 'FI', label: '🇫🇮 Finland' },
  { value: 'GR', label: '🇬🇷 Greece' },
  { value: 'LU', label: '🇱🇺 Luxembourg' }
];

const TABS = [
  { id: 'overview', label: 'Overview', needsData: false },
  { id: 'identity', label: 'Identity', needsData: false },
  { id: 'access', label: 'Access', needsData: false },
  { id: 'commercial', label: 'Commercial', needsData: false },
  { id: 'club', label: 'Club', needsData: false },
  { id: 'pieces', label: 'Pieces', needsData: false },
  { id: 'communications', label: 'Communications', needsData: false },
  { id: 'orders', label: 'Orders', needsData: true },
  { id: 'nfc', label: 'NFC', needsData: true },
  { id: 'post', label: 'Post', needsData: true },
  { id: 'silencios', label: 'Silencios', needsData: false },
  { id: 'tags-notes', label: 'Tags & Notes', needsData: false },
  { id: 'incidences', label: 'Incidences', needsData: true },
];

function computeCustomerRating(profile) {
  const pieces = Math.min((profile.pieces?.length || profile.piece_count || 0), 3);
  const years = profile.commercial?.first_purchase_at
    ? Math.min(Math.floor((Date.now() - new Date(profile.commercial.first_purchase_at)) / (365 * 24 * 60 * 60 * 1000)), 3)
    : 0;
  const moments = Math.min((profile.club?.moments_shared || 0), 3);
  const washes = Math.min((profile.club?.total_washes || 0), 3);
  const total = pieces + years + moments + washes;
  let tier = '3TOP';
  if (total >= 10) tier = '1TOP';
  else if (total >= 7) tier = '2TOP';
  return { pieces, years, moments, washes, stars: total, tier };
}


function getFlagEmoji(countryCode) {
  const code = (countryCode || '').toUpperCase();
  if (!code || code.length !== 2) return '—';
  // Regional Indicator Symbols: A=127462, B=127463, etc.
  const base = 127397;
  const emoji = String.fromCodePoint(...code.split('').map(c => c.charCodeAt(0) + base));
  return emoji;
}

let currentCustomerId = null;
let currentProfile = null;
let currentRoot = null;
let activeAlertEntry = null;
let lastEditedField = null;
let activeTab = 'overview';
let tabDataCache = {};
let tabLoading = {};

export async function renderMemberDetail(root, customerId, initialTab = 'overview') {
  currentRoot = root;
  currentCustomerId = customerId;
  activeTab = sessionStorage.getItem(`potisse_tab_${customerId}`) || initialTab || 'overview';
  // Push 5.5: si venimos de una navegación forzada (ej. desde Incidences global),
  // limpiamos para que la próxima visita a este member abra en Overview.
  sessionStorage.removeItem(`potisse_tab_${customerId}`);
  tabDataCache = {};
  tabLoading = {};
  root.innerHTML = '<div class="tab-content"><div class="empty-state"><p class="empty-state-text">Loading...</p></div></div>';

  try {
    const [profileData, alertsData] = await Promise.all([
      api.get(`members/${customerId}/profile`),
      api.get('access-alerts')
    ]);
    const syncStatusData = null;
    currentProfile = profileData;
    currentProfile._liveSync = syncStatusData || {};
    activeAlertEntry = findActiveAlert(alertsData, customerId);
    render();
    // v6.9.2: auto-sync eliminado — el usuario decide cuando sincronizar
  } catch (err) {
    root.innerHTML = `
      <div class="tab-content">
        <div class="empty-state">
          <p class="empty-state-text">${escapeHtml(err.message || 'Failed to load member.')}</p>
          <button type="button" class="btn btn-sm btn-secondary" id="mv-retry" style="margin-top: var(--space-3);">Retry</button>
        </div>
      </div>
    `;
    root.querySelector('#mv-retry').addEventListener('click', () => renderMemberDetail(root, customerId));
  }
}

function findActiveAlert(alertsData, customerId) {
  const idNum = Number(customerId);
  const all = [...(alertsData.iberian || []), ...(alertsData.european || [])];
  return all.find((e) => e.customer_id === idNum) || null;
}

async function refresh() {
  const savedTab = activeTab;
  tabDataCache = {};
  await renderMemberDetail(currentRoot, currentCustomerId, savedTab);
  window.dispatchEvent(new CustomEvent('members:refresh'));
}

// ═══════════════════════════════════════════════════════════════════════
// RENDER PRINCIPAL
// ═══════════════════════════════════════════════════════════════════════
function render() {
  const p = currentProfile;
  // Inject sync indicator CSS if not present
  if (!document.getElementById('sync-indicator-styles')) {
    const style = document.createElement('style');
    style.id = 'sync-indicator-styles';
    style.textContent = `
      .sync-badge { display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 50%; font-size: 11px; font-weight: 700; line-height: 1; margin-left: 6px; cursor: default; }
      .sync-synced { background: rgba(76,175,80,0.15); color: var(--success); border: 1.5px solid var(--success); }
      .sync-pending { background: rgba(255,193,7,0.15); color: var(--warning); border: 1.5px solid var(--warning); animation: sync-pulse 1.5s infinite; }
      .sync-failed { background: rgba(244,67,54,0.15); color: var(--danger); border: 1.5px solid var(--danger); }
      .sync-unknown { background: var(--hairline); color: var(--muted); border: 1.5px solid var(--muted); }
      .sync-line { display: inline-flex; align-items: center; gap: 6px; }
      .sync-divergence-banner { background: rgba(244,67,54,0.06); border: 1px solid rgba(244,67,54,0.25); border-radius: 4px; padding: var(--space-2) var(--space-3); margin-left: var(--space-2); }
      .sync-customer-edit-banner { background: rgba(184,134,61,0.08); border: 1px solid rgba(184,134,61,0.35); border-radius: 4px; padding: var(--space-2) var(--space-3); margin-left: var(--space-2); }
      .sync-legend { font-size: var(--size-xs); color: var(--muted); margin: var(--space-1) 0 var(--space-2) 0; }
      .sync-actions { display: flex; gap: var(--space-2); align-items: center; flex-wrap: wrap; }
      .sync-details-panel { margin-top: var(--space-2); padding-top: var(--space-2); border-top: 1px solid var(--hairline); font-size: var(--size-xs); color: var(--muted); }
      .sync-details-panel strong { color: var(--potisse-chocolate); }
      .toast-undo { position: fixed; bottom: 24px; right: 24px; background: var(--surface); border: 1px solid var(--hairline); border-radius: 6px; padding: var(--space-3) var(--space-4); box-shadow: 0 4px 16px rgba(0,0,0,0.12); display: flex; align-items: center; gap: var(--space-3); z-index: 9999; animation: toast-slide-in 0.3s ease; }
      .toast-undo button { white-space: nowrap; }
      @keyframes sync-pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
      @keyframes toast-slide-in { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    `;
    document.head.appendChild(style);
  }
  const hasName = !!(p.identity.first_name || p.identity.last_name);
  const name = hasName ? `${p.identity.first_name || ''} ${p.identity.last_name || ''}`.trim() : null;
  const rating = computeCustomerRating(p);

  currentRoot.innerHTML = `
    <div class="member-view-header">
      <div class="member-view-title">
        <button type="button" class="btn btn-sm btn-secondary" id="mv-back">&larr; Back to list</button>
        <span class="member-view-name">${name ? escapeHtml(name) : '<span class="ph" style="font-style:italic;">Sin nombre</span>'}</span>
        ${!name ? '<button type="button" class="btn btn-sm btn-secondary" id="mv-add-name">Add name</button>' : ''}
        ${p.identity.language ? `<span class="chip">${escapeHtml(p.identity.language)}</span>` : ''}
        
      </div>
      <div class="member-view-actions">
        ${actionButtonsMarkup()}
      </div>
    </div>
    <div class="tab-content">
      ${blockRating(rating, p)}
      <nav class="member-tabs" id="member-tab-bar">
        ${TABS.map((t) => `<button type="button" class="member-tab${activeTab === t.id ? ' active' : ''}" data-tab="${t.id}">${t.label}</button>`).join('')}
      </nav>
      <div class="member-tab-panels">
        ${TABS.map((t) => `<div class="member-tab-panel${activeTab === t.id ? ' active' : ''}" data-panel="${t.id}">${renderTabPanel(t.id)}</div>`).join('')}
      </div>
    </div>
  `;
  wireEvents();
  loadTabDataIfNeeded(activeTab);

  if (lastEditedField) {
    const el = currentRoot.querySelector(`[data-field="${lastEditedField}"]`);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    lastEditedField = null;
  }
}

function renderTabPanel(tabId) {
  switch (tabId) {
    case 'overview': return renderOverviewPanel();
    case 'identity': return renderIdentityPanel();
    case 'access': return renderAccessPanel();
    case 'commercial': return renderCommercialPanel();
    case 'club': return renderClubPanel();
    case 'pieces': return renderPiecesPanel();
    case 'communications': return renderCommunicationsPanel();
    case 'orders': return renderOrdersPanel();
    case 'nfc': return renderNfcPanel();
    case 'post': return renderPostPanel();
    case 'silencios': return renderSilenciosPanel();
    case 'tags-notes': return renderTagsNotesPanel();
    case 'incidences': return renderIncidencesPanel();
    default: return '<div class="tab-panel-inner"><p class="empty-state-text">Unknown tab.</p></div>';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 1: OVERVIEW
// ═══════════════════════════════════════════════════════════════════════
function renderOverviewPanel() {
  const p = currentProfile;
  const id = p.identity;
  const rating = computeCustomerRating(p);
  const a = p.access_status;
  const stateLabel = { entered: 'Entered', waiting: 'Waiting', overdue: 'Overdue', unknown: 'Unknown' }[a.state] || 'Unknown';
  const stateBadgeClass = { entered: 'badge-success', waiting: 'badge-warning', overdue: 'badge-danger', unknown: 'badge-neutral' }[a.state] || 'badge-neutral';

  return `
    <div class="tab-panel-inner">
      <div class="overview-grid">
        <div class="overview-sidebar">
          <div class="member-rating" style="margin-bottom: var(--space-4);">
            <div class="rating-header">
              <span class="rating-flag">${escapeHtml(getFlagEmoji(id.country || p.country))}</span>
              <span class="rating-tier">${rating.tier}</span>
              ${rating.stars >= 10 ? '<span class="rating-vip">VIP</span>' : ''}
            </div>
            <div class="rating-score">
              ${renderStars(rating.stars)}
              <span class="rating-num">${rating.stars}/12</span>
            </div>
            <div class="rating-breakdown">
              <span>Pieces ${rating.pieces}★</span>
              <span>Years ${rating.years}★</span>
              <span>Moments ${rating.moments}★</span>
              <span>Washes ${rating.washes}★</span>
            </div>
          </div>
          <div class="card" style="padding: var(--space-4);">
            <div class="stat-label">Access</div>
            <div style="margin-top: var(--space-2);"><span class="badge ${stateBadgeClass}">${stateLabel}</span></div>
            <div class="card-meta" style="margin-top: var(--space-2);">Zone: ${escapeHtml(a.zone || '—')}</div>
          </div>
        </div>
        <div class="overview-main">
          <div class="section-heading" style="margin-top:0;">At a glance</div>
          <div class="field-grid" style="max-width: 100%;">
            <div class="field-label">Email</div>
            <div class="field-value-readonly">${fieldDisplayReadonly(id.email)}</div>
            <div class="field-label">Phone</div>
            <div class="field-value-readonly">${fieldDisplayReadonly(id.phone)}</div>
            <div class="field-label">Address</div>
            <div class="field-value-readonly">${fieldDisplayReadonly(id.address_line1 || id.address)}</div>
            <div class="field-label">City</div>
            <div class="field-value-readonly">${fieldDisplayReadonly(id.city)}</div>
            <div class="field-label">Country</div>
            <div class="field-value-readonly">${id.country ? escapeHtml(id.country.toUpperCase()) + '<span class="edit-hint">✎</span>' : '<span class="ph">—</span><span class="edit-hint">✎</span>'}</div>
            <div class="field-label">Language</div>
            <div class="field-value-readonly">${id.language ? escapeHtml(id.language) + '<span class="edit-hint">✎</span>' : '<span class="ph">—</span><span class="edit-hint">✎</span>'}</div>
            <div class="field-label">Registered</div>
            <div>${fmtDate(p.commercial.registered_at)}</div>
            <div class="field-label">Orders</div>
            <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${p.commercial.orders_count}</div>
            <div class="field-label">Club visits</div>
            <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${p.club?.club_visits_count || 0}</div>
            <div class="field-label">Pieces</div>
            <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${p.pieces?.length || 0}</div>
          </div>
          ${activeAlertEntry ? `
            <div class="banner-info" style="background: rgba(184,134,61,0.15); border-color: var(--warning); margin-top: var(--space-4);">
              Alert active since ${fmtDate(activeAlertEntry.fulfillment_date)} — ${activeAlertEntry.days_since_fulfillment} days elapsed.
              <a href="#/access-alerts">View in Access alerts &rarr;</a>
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 2: IDENTITY
// ═══════════════════════════════════════════════════════════════════════
function renderIdentityPanel() {
  const id = currentProfile.identity;
  const customerId = currentProfile.customer_id || currentProfile.id;
  const lastSync = currentProfile.last_synced_from_shopify_at;
  const timeLabel = lastSync ? timeAgo(lastSync) : 'Not yet synced';

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <div class="shopify-info-banner" style="background:var(--bg-2);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px;font-size:var(--size-sm);color:var(--muted);">
          <p style="margin:0 0 8px 0;">PII data is managed in Shopify. To modify customer profile fields, open <a href="https://admin.shopify.com/store/${escapeHtml(window.SHOPIFY_STORE_DOMAIN || '')}/customers/${customerId}" target="_blank" style="color:var(--primary);text-decoration:underline;">Shopify Admin →</a></p>
          <p style="margin:0 0 8px 0;font-size:var(--size-xs);">Only the customer's default address is shown here. If they have multiple addresses in Shopify, only the default is synced.</p>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-top:8px;">
            <span style="font-size:var(--size-xs);color:var(--muted);">Last synced from Shopify: <span style="color:var(--text);font-weight:500;">${escapeHtml(timeLabel)}</span></span>
            <button type="button" class="btn btn-xs btn-secondary" id="mv-refresh-shopify">⟳ Refresh from Shopify</button>
          </div>
        </div>
        <div style="margin-bottom:12px;font-size:var(--size-xs);color:var(--muted);text-align:right;">
          <a href="https://admin.shopify.com/store/${escapeHtml(window.SHOPIFY_STORE_DOMAIN || '')}/customers/${customerId}" target="_blank" style="color:var(--primary);text-decoration:underline;">Edit in Shopify Admin →</a>
        </div>
        <h2 class="section-heading" style="margin-top:0;">Identity</h2>
        <div class="field-grid">
          <div class="field-label">First name</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.first_name)}</div>
          <div class="field-label">Last name</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.last_name)}</div>
          <div class="field-label">Email</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.email)}</div>
          <div class="field-label">Phone</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.phone)}</div>
          <div class="field-label">Address</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.address_line1 || id.address)}</div>
          <div class="field-label">Apartment / Floor</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.address_line2)}</div>
          <div class="field-label">City</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.city)}</div>
          <div class="field-label">Province</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.province)}</div>
          <div class="field-label">Postal Code</div>
          <div class="field-value readonly-field">${fieldDisplayReadonly(id.postal_code)}</div>
          <div class="field-label">Country</div>
          <div class="field-value readonly-field">${id.country ? escapeHtml(id.country.toUpperCase()) : '<span class="ph">—</span>'}</div>
          <div class="field-label">Language</div>
          <div class="field-value" data-field="language">${id.language ? escapeHtml(id.language) + '<span class="edit-hint">✎</span>' : '<span class="ph">—</span><span class="edit-hint">✎</span>'}</div>
          <div class="field-label">Private notes</div>
          <div class="field-value" data-field="private_notes">${fieldDisplay(id.private_notes)}</div>
        </div>
      </section>
    </div>
  `;
}

async function handleRefreshFromShopify() {
  const customerId = currentProfile.customer_id || currentProfile.id;
  const btn = document.getElementById('mv-refresh-shopify');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Loading...';
  }

  try {
    const res = await fetch(`/api/proxy/admin/members/${customerId}/refresh-from-shopify`);
    const data = await res.json();

    if (!data.ok) {
      showToast(`Shopify error: ${data.error || 'Unknown'}`, 'error');
      return;
    }

    if (data.in_sync) {
      showToast('Everything is up to date. No changes.', 'success');
      return;
    }

    showRefreshPreviewModal(data.diff);
  } catch (err) {
    showToast('Failed to fetch from Shopify. Try again later.', 'error');
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = '⟳ Refresh from Shopify';
    }
  }
}

function showRefreshPreviewModal(diff) {
  const customerId = currentProfile.customer_id || currentProfile.id;
  const existing = document.getElementById('refresh-preview-modal');
  if (existing) existing.remove();

  const rows = diff.map(d => `
    <tr>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);font-weight:500;">${escapeHtml(d.field)}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);color:var(--muted);">${escapeHtml(d.kv ?? '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);color:var(--primary);font-weight:500;">${escapeHtml(d.shopify ?? '—')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid var(--border);text-align:center;"><input type="checkbox" class="refresh-checkbox" data-field="${escapeHtml(d.field)}" data-value="${escapeHtml(d.shopify ?? '')}" checked></td>
    </tr>
  `).join('');

  const modal = document.createElement('div');
  modal.id = 'refresh-preview-modal';
  modal.className = 'modal-overlay';
  modal.innerHTML = `
    <div class="modal" style="max-width:600px;width:90%;">
      <h3 class="modal-title">Update KV with Shopify data?</h3>
      <p style="margin-bottom:16px;color:var(--muted);font-size:var(--size-sm);">Select which fields to update from Shopify to the local KV store.</p>
      <table style="width:100%;border-collapse:collapse;font-size:var(--size-sm);margin-bottom:16px;">
        <thead>
          <tr style="text-align:left;border-bottom:2px solid var(--border);">
            <th style="padding:8px 12px;">Field</th>
            <th style="padding:8px 12px;">KV current</th>
            <th style="padding:8px 12px;">Shopify current</th>
            <th style="padding:8px 12px;text-align:center;">Apply</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" id="refresh-cancel">Cancel</button>
        <button type="button" class="btn btn-primary" id="refresh-apply">Apply selected fields</button>
      </div>
    </div>
  `;
  document.body.appendChild(modal);
  modal.style.display = 'flex';

  document.getElementById('refresh-cancel').onclick = () => modal.remove();
  document.getElementById('refresh-apply').onclick = async () => {
    const checked = modal.querySelectorAll('.refresh-checkbox:checked');
    const fields_to_apply = {};
    checked.forEach(cb => {
      fields_to_apply[cb.dataset.field] = cb.dataset.value || null;
    });

    if (Object.keys(fields_to_apply).length === 0) {
      showToast('No fields selected.', 'warning');
      return;
    }

    try {
      const res = await fetch(`/api/proxy/admin/members/${customerId}/apply-shopify-refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fields_to_apply })
      });
      const result = await res.json();
      if (result.ok) {
        showToast(`Updated. ${result.applied.length} fields synced from Shopify.`, 'success');
        modal.remove();
        loadMemberProfile(customerId);
      } else {
        showToast('Failed to apply changes. Try again.', 'error');
      }
    } catch (err) {
      showToast('Failed to apply changes. Try again.', 'error');
    }
  };
}


// ═══════════════════════════════════════════════════════════════════════
// TAB 3: ACCESS
// ═══════════════════════════════════════════════════════════════════════
function renderAccessPanel() {
  const a = currentProfile.access_status;
  const stateBadge = {
    entered: '<span class="badge badge-success">&check; Entered</span>',
    waiting: '<span class="badge badge-warning">&#9675; Waiting</span>',
    overdue: '<span class="badge badge-danger">! Overdue</span>'
  }[a.state] || '<span class="badge badge-neutral">&#9675; Unknown</span>';

  const alertBanner = activeAlertEntry
    ? `<div class="banner-info" style="background: rgba(184,134,61,0.15); border-color: var(--warning);">
        Alert active since ${fmtDate(activeAlertEntry.fulfillment_date)} — ${activeAlertEntry.days_since_fulfillment} days elapsed.
        <a href="#/access-alerts">View in Access alerts &rarr;</a>
      </div>`
    : '';

  const history = (a.history || []).slice(-10).reverse();
  const historyMarkup = history.length
    ? `<table class="data-table"><thead><tr><th>Timestamp</th><th>Action</th></tr></thead><tbody>
        ${history.map((h) => `<tr><td>${fmtDateTime(h.timestamp)}</td><td>${escapeHtml(h.action)}</td></tr>`).join('')}
      </tbody></table>`
    : '<p class="empty-state-text">No actions recorded yet.</p>';

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Access status</h2>
        <p>${stateBadge} ${a.zone ? `<span class="card-meta">Zone: ${escapeHtml(a.zone)}</span>` : ''}</p>
        ${a.state === 'unknown' ? '<div class="banner-info">Access status derivation pending — visible once implemented.</div>' : ''}
        ${alertBanner}
        <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Recent actions</h3>
        ${historyMarkup}
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 4: COMMERCIAL
// ═══════════════════════════════════════════════════════════════════════
function renderCommercialPanel() {
  const c = currentProfile.commercial;
  const totalSpent = c.total_spent != null ? `€${Number(c.total_spent).toFixed(2)}` : '<span class="ph">—</span>';
  const aov = c.aov != null ? `€${Number(c.aov).toFixed(2)}` : '<span class="ph">—</span>';
  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Commercial presence</h2>
        <div class="field-grid">
          <div class="field-label">Registered</div>
          <div>${fmtDate(c.registered_at)}</div>
          <div class="field-label">First purchase</div>
          <div>${fmtDate(c.first_purchase_at)}</div>
          <div class="field-label">Last purchase</div>
          <div>${fmtDate(c.last_purchase_at)}</div>
          <div class="field-label">Orders</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${c.orders_count}</div>
          <div class="field-label">Total spent</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${totalSpent}</div>
          <div class="field-label">AOV</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${aov}</div>
        </div>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 5: CLUB
// ═══════════════════════════════════════════════════════════════════════
function renderClubPanel() {
  const c = currentProfile.club;
  const sessions = (c.recent_sessions || []).slice(0, 10);
  const sessionsMarkup = sessions.length
    ? `<table class="data-table"><thead><tr><th>Timestamp</th><th>Device</th></tr></thead><tbody>
        ${sessions.map((s) => `<tr><td>${fmtDateTime(s.timestamp)}</td><td><span class="ph">${escapeHtml(s.device || 'Unknown')}</span></td></tr>`).join('')}
      </tbody></table>`
    : '<p class="empty-state-text">No sessions yet.</p>';

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Club presence</h2>
        <div class="field-grid">
          <div class="field-label">First club entry</div>
          <div>${fmtDate(c.first_club_entry_at)}</div>
          <div class="field-label">Club visits</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${c.club_visits_count || 0}</div>
          <div class="field-label">Last visit</div>
          <div>${fmtDateTime(c.last_visit)}</div>
          <div class="field-label">Total washes</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${c.total_washes || 0}</div>
          <div class="field-label">Moments shared</div>
          <div class="stat-inline" style="text-align: left; font-size: var(--size-lg);">${c.moments_shared || 0}</div>
          <div class="field-label">Post history</div>
          <div>
            <span class="badge badge-success">Kept ${c.post_history?.kept || 0}</span>
            <span class="badge badge-info">Published ${c.post_history?.published || 0}</span>
            <span class="badge badge-neutral">Discarded ${c.post_history?.discarded || 0}</span>
          </div>
        </div>
        <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Recent sessions</h3>
        ${sessionsMarkup}
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 6: PIECES
// ═══════════════════════════════════════════════════════════════════════
const RHYTHM_LABELS = {
  discovering: 'still finding her shape',
  settling: 'settling into you',
  established: 'this is who she is now'
};

function renderPiecesPanel() {
  const pieces = currentProfile.pieces || [];
  if (pieces.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">Pieces</h2>
          <div class="empty-state"><p class="empty-state-text">No pieces yet.</p></div>
        </section>
      </div>
    `;
  }
  const rows = pieces.map((p) => {
    const retractCount = (p.retract_history || []).length;
    const retractTitle = retractCount > 0 ? (p.retract_history || []).map((d) => fmtDate(d)).join(', ') : '';
    return `
      <tr>
        <td class="col-mono">${p.sku ? escapeHtml(p.sku) : '<span class="ph">—</span>'}</td>
        <td>${escapeHtml(p.product_name || '')}</td>
        <td>${fmtDate(p.purchase_date)}</td>
        <td>${fmtDate(p.first_tap_at)}</td>
        <td class="col-num-center">${p.wash_count || 0}</td>
        <td><span class="badge badge-info" title="${escapeHtml(p.rhythm_phase || '')}">${escapeHtml(RHYTHM_LABELS[p.rhythm_phase] || p.rhythm_phase || '—')}</span></td>
        <td class="col-num-center${retractCount === 0 ? ' ph' : ''}" title="${escapeHtml(retractTitle)}">${retractCount}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Pieces</h2>
        <table class="data-table">
          <thead>
            <tr><th>SKU</th><th>Product</th><th>Purchase date</th><th>First tap</th>
            <th class="col-num-center">Washes</th><th>Rhythm phase</th><th class="col-num-center">Retracts</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 7: COMMUNICATIONS
// ═══════════════════════════════════════════════════════════════════════
function renderCommunicationsPanel() {
  const emails = currentProfile.communications?.email_timeline || [];
  if (emails.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">Communications</h2>
          <div class="empty-state"><p class="empty-state-text">No emails exchanged yet.</p></div>
        </section>
      </div>
    `;
  }
  const sorted = [...emails].sort((a, b) => new Date(b.timestamp || b.sent_at) - new Date(a.timestamp || a.sent_at));
  const items = sorted.map((e) => {
    const isInbound = e.direction === 'inbound';
    const openedBadge = e.opened_at ? '<span class="badge badge-success">Opened</span>' : '';
    return `
      <div class="timeline-email-item">
        <div>${isInbound ? '&#8592;' : '&#8594;'}</div>
        <div style="flex: 1;">
          <div><strong>${escapeHtml(e.template_id || 'custom')}</strong> — ${escapeHtml(e.subject || '')} ${openedBadge}</div>
          <div class="card-meta" title="${fmtDateTime(e.timestamp || e.sent_at)}">${timeAgo(e.timestamp || e.sent_at)}</div>
        </div>
      </div>
    `;
  }).join('');

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Communications</h2>
        ${items}
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 8: ORDERS (lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════
function renderOrdersPanel() {
  const data = tabDataCache['orders'];
  if (tabLoading['orders']) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading orders...</p></div></div>`;
  }
  if (data === null) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Failed to load orders.</p></div></div>`;
  }
  if (data === undefined) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading...</p></div></div>`;
  }
  const orders = data.orders || [];
  if (orders.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">Orders</h2>
          <div class="empty-state"><p class="empty-state-text">No orders found for this customer.</p></div>
        </section>
      </div>
    `;
  }
  const rows = orders.map((o) => `
    <tr>
      <td class="col-mono">${escapeHtml(o.order_id || o.id || '—')}</td>
      <td>${fmtDate(o.created_at || o.date)}</td>
      <td><span class="badge badge-${o.status === 'fulfilled' ? 'success' : o.status === 'cancelled' ? 'danger' : 'info'}">${escapeHtml(o.status || 'unknown')}</span></td>
      <td class="col-num">${o.total_price || o.total || '—'}</td>
      <td>${escapeHtml(o.currency || 'EUR')}</td>
      <td class="col-num">${(o.line_items || []).length}</td>
    </tr>
  `).join('');

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Orders</h2>
        <table class="data-table">
          <thead>
            <tr><th>Order ID</th><th>Date</th><th>Status</th><th>Total</th><th>Currency</th><th>Items</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 9: NFC (lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════
function renderNfcPanel() {
  const data = tabDataCache['nfc'];
  if (tabLoading['nfc']) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading NFC history...</p></div></div>`;
  }
  if (data === null) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Failed to load NFC history.</p></div></div>`;
  }
  if (data === undefined) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading...</p></div></div>`;
  }
  const taps = data.taps || data.history || [];
  const cards = data.cards || [];
  if (taps.length === 0 && cards.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">NFC History</h2>
          <div class="empty-state"><p class="empty-state-text">No NFC activity recorded.</p></div>
        </section>
      </div>
    `;
  }

  const cardsMarkup = cards.length ? `
    <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Cards</h3>
    <table class="data-table">
      <thead><tr><th>UID</th><th>Registered</th><th>Pieces</th><th>Last tap</th></tr></thead>
      <tbody>${cards.map((c) => `
        <tr>
          <td class="col-mono">${escapeHtml(c.uid || '—')}</td>
          <td>${fmtDateTime(c.registered_at)}</td>
          <td class="col-num-center">${c.piece_count || 0}</td>
          <td>${fmtDateTime(c.last_tap_at)}</td>
        </tr>
      `).join('')}</tbody>
    </table>
  ` : '';

  const tapsMarkup = taps.length ? `
    <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Tap history</h3>
    <div class="nfc-timeline">
      ${taps.map((t) => `
        <div class="nfc-timeline-item">
          <div class="nfc-timeline-dot ${t.outcome === 'success' ? 'success' : 'denied'}"></div>
          <div style="flex:1;">
            <div><strong>${escapeHtml(t.outcome || 'unknown')}</strong> <span class="card-meta">&middot; CTR ${t.ctr || '—'}</span></div>
            <div class="card-meta">${fmtDateTime(t.timestamp)} &middot; ${escapeHtml(t.device || 'Unknown device')}</div>
            ${t.piece_id ? `<div class="card-meta">Piece: <span class="col-mono">${escapeHtml(t.piece_id)}</span></div>` : ''}
          </div>
        </div>
      `).join('')}
    </div>
  ` : '';

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">NFC History</h2>
        ${cardsMarkup}
        ${tapsMarkup}
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 10: POST (lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════
function renderPostPanel() {
  const data = tabDataCache['post'];
  if (tabLoading['post']) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading posts...</p></div></div>`;
  }
  if (data === null) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Failed to load posts.</p></div></div>`;
  }
  if (data === undefined) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading...</p></div></div>`;
  }
  const posts = data.posts || [];
  if (posts.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">Posts</h2>
          <div class="empty-state"><p class="empty-state-text">No posts from this customer.</p></div>
        </section>
      </div>
    `;
  }
  const items = posts.map((p) => `
    <div class="post-mini-card">
      <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom: var(--space-2);">
        <span class="badge badge-${p.status === 'published' ? 'success' : p.status === 'kept' ? 'info' : p.status === 'discarded' ? 'danger' : 'neutral'}">${escapeHtml(p.status || 'pending')}</span>
        <span class="card-meta">${timeAgo(p.submitted_at || p.created_at)}</span>
      </div>
      ${p.caption ? `<p style="font-style: italic; font-size: var(--size-sm); margin-bottom: var(--space-2);">"${escapeHtml(p.caption)}"</p>` : ''}
      ${p.piece_id ? `<div class="card-meta">Piece: <span class="col-mono">${escapeHtml(p.piece_id)}</span></div>` : ''}
      ${p.published_at ? `<div class="card-meta">Published: ${fmtDateTime(p.published_at)}</div>` : ''}
    </div>
  `).join('');

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Posts</h2>
        ${items}
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 11: SILENCIOS
// ═══════════════════════════════════════════════════════════════════════
function renderSilenciosPanel() {
  const s = currentProfile.silencios_received || {};
  function renderList(entries, emptyText) {
    if (!entries || entries.length === 0) {
      return `<p class="empty-state-text">${emptyText}</p>`;
    }
    return `<ul style="margin: 0; padding-left: var(--space-4); font-size: var(--size-sm);">
      ${entries.map((e) => `<li>${fmtDate(e.last_purchase_at || e.timestamp)} — ${e.is_candidate ? 'candidate' : (e.tag_applied ? 'applied' : 'not applied')}</li>`).join('')}
    </ul>`;
  }
  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Silencios received</h2>
        <h3 class="card-title" style="margin-bottom: var(--space-2);">Silencio 1</h3>
        ${renderList(s.silencio_1, 'No Silencio 1 sent yet.')}
        <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Silencio 2</h3>
        <p class="empty-state-text">No Silencio 2 sent yet.</p>
        <h3 class="card-title" style="margin-top: var(--space-4); margin-bottom: var(--space-2);">Silencio 3</h3>
        <p class="empty-state-text">No Silencio 3 sent yet.</p>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 12: TAGS & NOTES
// ═══════════════════════════════════════════════════════════════════════
function renderTagsNotesPanel() {
  const tags = currentProfile.tags_shopify || [];
  const notes = currentProfile.notes_free || '';
  const pills = tags.length
    ? tags.map((t) => `
        <span class="badge badge-info" style="margin-right: 4px;">
          ${escapeHtml(t)} <span class="tag-remove-x" data-tag="${escapeHtml(t)}" style="cursor: pointer; margin-left: 4px;">&times;</span>
        </span>
      `).join('')
    : '<span class="ph">No tags yet.</span>';

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Shopify tags</h2>
        <div style="margin-bottom: var(--space-3);">${pills}</div>
        <input type="text" class="toolbar-search" id="mv-add-tag" placeholder="Type tag name and press Enter" style="max-width: 280px;">
      </section>
      <section class="member-block" style="border-bottom:none;">
        <h2 class="section-heading">Free notes</h2>
        <textarea id="mv-notes-free" rows="6" style="width: 100%; max-width: 640px; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);" placeholder="Add private notes about this customer...">${escapeHtml(notes)}</textarea>
        <div style="max-width: 640px; text-align: right; margin-top: var(--space-2);">
          <button type="button" class="btn btn-sm btn-primary" id="mv-notes-save" style="display: none;">Save notes</button>
        </div>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 13: INCIDENCES (lazy-loaded)
// ═══════════════════════════════════════════════════════════════════════
function renderIncidencesPanel() {
  const data = tabDataCache['incidences'];
  if (tabLoading['incidences']) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading incidences...</p></div></div>`;
  }
  if (data === null) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Failed to load incidences.</p></div></div>`;
  }
  if (data === undefined) {
    return `<div class="tab-panel-inner"><div class="empty-state"><p class="empty-state-text">Loading...</p></div></div>`;
  }
  const incidences = data.incidences || [];
  if (incidences.length === 0) {
    return `
      <div class="tab-panel-inner">
        <section class="member-block" style="padding-top:0; border-bottom:none;">
          <h2 class="section-heading" style="margin-top:0;">Incidences</h2>
          <div class="empty-state"><p class="empty-state-text">No incidences recorded for this customer.</p></div>
        </section>
      </div>
    `;
  }

  const severityBadge = {
    low: 'badge-neutral',
    medium: 'badge-info',
    high: 'badge-warning',
    critical: 'badge-danger'
  };
  const statusBadge = {
    open: 'badge-danger',
    in_progress: 'badge-warning',
    resolved: 'badge-success',
    closed: 'badge-neutral'
  };

  const rows = incidences.map((inc) => `
    <div class="incidence-card" data-incidence-id="${escapeHtml(inc.incidence_id)}">
      <div class="incidence-header">
        <div class="incidence-badges">
          <span class="badge ${severityBadge[inc.severity] || 'badge-neutral'}">${escapeHtml(inc.severity)}</span>
          <span class="badge ${statusBadge[inc.status] || 'badge-neutral'}">${escapeHtml(inc.status)}</span>
          ${inc.assigned_to ? `<span class="badge badge-info" title="Assigned to">&#128100; ${escapeHtml(inc.assigned_to)}</span>` : ''}
        </div>
        <div class="incidence-actions" style="display: flex; align-items: center; gap: 8px;">
          <span class="card-meta">${timeAgo(inc.created_at)}</span>
          <button type="button" class="btn btn-xs btn-secondary incidence-edit-btn" data-id="${escapeHtml(inc.incidence_id)}">Edit</button>
          ${inc.status === 'open' ? `<button type="button" class="btn btn-xs btn-secondary incidence-resolve-btn" data-id="${escapeHtml(inc.incidence_id)}">Resolve</button>` : ''}
        </div>
      </div>
      <h4 class="incidence-title">${escapeHtml(inc.title)}</h4>
      ${inc.description ? `<p class="incidence-desc">${escapeHtml(inc.description)}</p>` : ''}
      ${inc.order_id ? `<div class="card-meta">Order: <span class="col-mono">${escapeHtml(inc.order_id)}</span></div>` : ''}
      ${inc.piece_id ? `<div class="card-meta">Piece: <span class="col-mono">${escapeHtml(inc.piece_id)}</span></div>` : ''}
      ${inc.status === 'open' ? `<button type="button" class="btn btn-sm btn-secondary incidence-resolve-btn" data-id="${escapeHtml(inc.incidence_id)}">Mark resolved</button>` : ''}
    </div>
  `).join('');

  return `
    <div class="tab-panel-inner">
      <section class="member-block" style="padding-top:0; border-bottom:none;">
        <h2 class="section-heading" style="margin-top:0;">Incidences</h2>
        <div class="incidences-list">${rows}</div>
      </section>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// LAZY DATA LOADING
// ═══════════════════════════════════════════════════════════════════════
async function loadTabDataIfNeeded(tabId) {
  const tab = TABS.find((t) => t.id === tabId);
  if (!tab || !tab.needsData) return;
  if (tabDataCache[tabId] !== undefined) return;
  if (tabLoading[tabId]) return;

  tabLoading[tabId] = true;
  refreshTabPanel(tabId);

  try {
    let endpoint;
    switch (tabId) {
      case 'orders': endpoint = `members/${currentCustomerId}/orders`; break;
      case 'nfc': endpoint = `members/${currentCustomerId}/nfc-history`; break;
      case 'post': endpoint = `members/${currentCustomerId}/posts`; break;
      case 'incidences': endpoint = `members/${currentCustomerId}/incidences`; break;
      default: return;
    }
    const data = await api.get(endpoint);
    tabDataCache[tabId] = data;
  } catch (err) {
    console.error(`[Tab ${tabId}] Load failed:`, err.message);
    tabDataCache[tabId] = null;
  } finally {
    tabLoading[tabId] = false;
    refreshTabPanel(tabId);
  }
}

function refreshTabPanel(tabId) {
  if (!currentRoot) return;
  const panel = currentRoot.querySelector(`.member-tab-panel[data-panel="${tabId}"]`);
  if (!panel) return;
  const tab = TABS.find((t) => t.id === tabId);
  if (tab && tab.needsData && tabDataCache[tabId] === undefined && !tabLoading[tabId]) {
    loadTabDataIfNeeded(tabId);
    return;
  }
  panel.innerHTML = renderTabPanel(tabId);
  wireTabSpecificEvents(tabId);
}

// ═══════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════
function fieldDisplay(value) {
  if (value) return escapeHtml(value) + '<span class="edit-hint">✎</span>';
  return '<span class="ph">—</span><span class="edit-hint">✎</span>';
}

function fieldDisplayReadonly(value) {
  if (value) return escapeHtml(value);
  return '<span class="ph">—</span>';
}function renderStars(score, max = 5) {
  const filled = Math.min(Math.floor(score / 2.4), max);
  const half = (score / 2.4) - filled >= 0.5 ? 1 : 0;
  const empty = max - filled - half;
  let html = '<span class="star-rating">';
  for (let i = 0; i < filled; i++) html += '<span class="star filled">★</span>';
  if (half) html += '<span class="star half">★</span>';
  for (let i = 0; i < empty; i++) html += '<span class="star">★</span>';
  html += '</span>';
  return html;
}

function blockRating(rating, profile) {
  const flag = getFlagEmoji(profile.identity?.country || profile.country);
  return `
    <div class="member-block member-rating" style="border-bottom:none; padding-bottom: var(--space-4);">
      <div class="rating-header">
        <span class="rating-flag" style="font-size: var(--size-lg);">${flag}</span>
        <span class="rating-tier">${rating.tier}</span>
        ${rating.stars >= 10 ? '<span class="rating-vip">VIP</span>' : ''}
      </div>
      <div class="rating-score">
        ${renderStars(rating.stars)}
        <span class="rating-num">${rating.stars}/12</span>
      </div>
      <div class="rating-breakdown">
        <span>Pieces ${rating.pieces}★</span>
        <span>Years ${rating.years}★</span>
        <span>Moments ${rating.moments}★</span>
        <span>Washes ${rating.washes}★</span>
      </div>
    </div>
  `;
}

// ═══════════════════════════════════════════════════════════════════════
// INLINE EDITING
// ═══════════════════════════════════════════════════════════════════════
function startFieldEdit(el, { value, type = 'text', selectOptions, onFinish, onAddressComponents }) {
  if (el.dataset.editing) return;
  el.dataset.editing = '1';

  let inputHtml;
  if (type === 'select') {
    inputHtml = `<select>${selectOptions.map((o) => `<option value="${escapeHtml(o.value)}"${o.value === (value || '') ? ' selected' : ''}>${escapeHtml(o.label)}</option>`).join('')}</select>`;
  } else if (type === 'textarea') {
    inputHtml = `<textarea rows="3">${escapeHtml(value || '')}</textarea>`;
  } else {
    inputHtml = `<input type="text" value="${escapeHtml(value || '')}">`;
  }
  el.innerHTML = inputHtml;
  const inputEl = el.querySelector('input,select,textarea');
  inputEl.focus();
  if (inputEl.select) inputEl.select();

  let done = false;

  function finish(shouldSave) {
    if (done) return;
    done = true;
    inputEl.removeEventListener('keydown', onKeyDown);
    inputEl.removeEventListener('blur', onBlur);
    if (type === 'select') inputEl.removeEventListener('change', onChange);
    onFinish(shouldSave ? inputEl.value : null);
  }

  function onKeyDown(e) {
    const isEnter = e.key === 'Enter' || e.keyCode === 13 || e.which === 13;
    const isEscape = e.key === 'Escape' || e.keyCode === 27 || e.which === 27;
    if (isEnter && type !== 'textarea') {
      e.preventDefault();
      e.stopPropagation();
      finish(true);
    } else if (isEscape) {
      e.preventDefault();
      e.stopPropagation();
      finish(false);
    }
  }

  function onBlur() {
    if (type === 'address') return;
    finish(true);
  }

  function onChange() {
    finish(true);
  }

  inputEl.addEventListener('keydown', onKeyDown);
  inputEl.addEventListener('blur', onBlur);
  if (type === 'select') inputEl.addEventListener('change', onChange);
  if (type === 'address') initAddressAutocomplete(inputEl, onAddressComponents);
}

function handleFieldClick(el) {
  const field = el.dataset.field;
  if (el.dataset.editing) return;

  const FIELD_CONFIG = {
    country: { type: 'select', value: currentProfile.identity.country, label: 'country', backendField: 'country', selectOptions: COUNTRY_OPTIONS },
    private_notes: { type: 'textarea', value: currentProfile.identity.private_notes, label: 'private notes', backendField: 'notes' },
    language: { type: 'select', value: currentProfile.identity.language, label: 'language', backendField: 'language', selectOptions: LANGUAGE_OPTIONS }
  };
  const config = FIELD_CONFIG[field];
  if (!config) return;

  let extractedComponents = null;

  startFieldEdit(el, {
    value: config.value,
    type: config.type,
    selectOptions: config.selectOptions,
    onAddressComponents: (components) => {
      extractedComponents = components;
      const cityEl = currentRoot.querySelector('[data-field="city"]');
      const provinceEl = currentRoot.querySelector('[data-field="province"]');
      const countryEl = currentRoot.querySelector('[data-field="country"]');
      const postalEl = currentRoot.querySelector('[data-field="postal_code"]');
      if (cityEl && components.city) cityEl.textContent = components.city;
      if (provinceEl && components.province) provinceEl.textContent = components.province;
      if (countryEl && components.country) countryEl.textContent = components.country.toUpperCase();
      if (postalEl && components.postal_code) postalEl.textContent = components.postal_code;
    },
    onFinish: (newValue) => {
      if (newValue === null) { render(); return; }
      const trimmed = newValue.trim();
      if (trimmed === (config.value || '') && !extractedComponents) { render(); return; }
      lastEditedField = field;
      if (config.sensitive) {
        toast('Email must be edited in Shopify Admin.', 'error'); render(); return;
      } else if (field === 'address') {
        toast('Address must be edited in Shopify Admin.', 'error');
        render();
        return;
      } else {
        handleIdentitySave(config.backendField, trimmed || null, config.label);
      }
    }
  });
}
const PII_FIELDS = ["first_name", "last_name", "email", "phone", "address_line1", "address_line2", "city", "province", "postal_code"];

async function handleIdentitySave(backendField, value, label) {
  if (PII_FIELDS.includes(backendField)) {
    console.error(`[GUARD] handleIdentitySave called with PII field ${backendField} — not allowed`);
    toast('PII edit not allowed. Use Shopify Admin.', 'error');
    return;
  }
  const displayVal = value || '(empty)';
  const ok = await confirmModal('Save changes?', `Save changes to ${escapeHtml(label)}: "${escapeHtml(displayVal)}"?`, 'Save', false);
  if (!ok) { render(); return; }
  try {
    await api.post(`admin/members/${currentCustomerId}/edit`, { [backendField]: value });
    toast('Saved.', 'success');
    await refresh();
  } catch (err) {
    toast(err.message || 'Save failed.', 'error');
    render();
  }
}

async function handleIdentitySaveMulti(fields, label) {
  const filtered = Object.fromEntries(
    Object.entries(fields).filter(([k]) => !PII_FIELDS.includes(k))
  );
  if (!Object.keys(filtered).length) {
    console.error(`[GUARD] handleIdentitySaveMulti: all fields blocked as PII`);
    return;
  }
  const displayVal = Object.entries(fields).map(([k, v]) => `${k}: ${v || '(empty)'}`).join(', ');
  const ok = await confirmModal('Save changes?', `Save changes to ${escapeHtml(label)}: "${escapeHtml(displayVal)}"?`, 'Save', false);
  if (!ok) { render(); return; }
  try {
    await api.post(`admin/members/${currentCustomerId}/edit`, filtered);
    toast('Saved.', 'success');
    await refresh();
  } catch (err) {
    toast(err.message || 'Save failed.', 'error');
    render();
  }
}

function saveUndoSnapshot(customerId, fields) {
  const snapshot = {};
  const identity = currentProfile.identity || {};
  for (const f of fields) {
    snapshot[f] = identity[f];
  }
  return snapshot;
}

function restoreUndoSnapshot(customerId) {

  if (!snap) return false;
  for (const [field, value] of Object.entries(snap.fields)) {
    if (currentProfile.identity) currentProfile.identity[field] = value;
  }

  render();
  toast('Cambios restaurados. Shopify no se ha modificado.', 'info');
  return true;
}

function clearUndoSnapshot(customerId) {

  if (snap && snap.timeoutId) clearTimeout(snap.timeoutId);
  if (snap && snap.toastEl) snap.toastEl.remove();

}

function showUndoToast(customerId, fields) {
  clearUndoSnapshot(customerId);

  const toastEl = document.createElement('div');
  toastEl.className = 'toast toast-undo';
  toastEl.innerHTML = `
    <span>Auto-sync: ${fields.join(', ')} actualizados desde Shopify.</span>
    <button type="button" class="btn btn-xs btn-secondary" id="undo-sync-${customerId}">Deshacer (30s)</button>
  `;
  document.body.appendChild(toastEl);

  const timeoutId = setTimeout(() => {

    toastEl.remove();
  }, 30000);



  toastEl.querySelector(`#undo-sync-${customerId}`).addEventListener('click', () => {
    clearTimeout(timeoutId);
    restoreUndoSnapshot(customerId);
    toastEl.remove();
  });
}

async

async function handleSyncDetailsToggle() {
  const panel = currentRoot.querySelector('#mv-sync-details');
  const btn = currentRoot.querySelector('#mv-sync-details-toggle');
  if (!panel || !btn) return;
  const isHidden = panel.style.display === 'none';
  panel.style.display = isHidden ? 'block' : 'none';
  btn.textContent = isHidden ? 'Ver detalles ↑' : 'Ver detalles ↓';
}
async function handleSendMagicLink() {
  const email = currentProfile.identity.email;
  const name = currentProfile.identity.first_name || 'this customer';
  const ok = await confirmModal('Send magic link?', `A magic link will be sent to ${escapeHtml(email || 'the customer email')}. The link opens the Club directly, valid for 15 minutes.`, 'Send', false);
  if (!ok) return;
  try {
    const result = await api.post('admin/magic-link', { customer_id: Number(currentCustomerId) });
    if (result.sent && result.email_id) {
      toast(`Magic link sent. Resend ID: ${result.email_id}`, 'success');
    } else if (result.sent) {
      toast('Magic link sent. Check your inbox (and spam).', 'success');
    } else {
      toast(`Failed: ${result.error || 'unknown'} — ${result.detail || ''}`, 'error');
    }
    await refresh();
  } catch (err) {
    const detail = err.data?.detail || err.data?.error || '';
    toast(`Failed: ${err.message}${detail ? ' — ' + detail : ''}`, 'error');
  }
}

async function handleSendEmail() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 560px;">
      <p class="modal-title">Send email</p>
      <div class="field-grid" style="grid-template-columns: 110px 1fr; gap: var(--space-3) var(--space-4);">
        <div class="field-label">Template</div>
        <div>
          <select id="email-template" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);">
            ${EMAIL_TEMPLATES.reduce((html, t, i, arr) => {
              const prev = arr[i - 1];
              const needsGroup = !prev || prev.category !== t.category;
              const closeGroup = prev && prev.category !== t.category;
              let out = html;
              if (closeGroup) out += '</optgroup>';
              if (needsGroup) out += `<optgroup label="${escapeHtml(t.category)}">`;
              out += `<option value="${t.value}">${escapeHtml(t.label)}</option>`;
              if (i === arr.length - 1) out += '</optgroup>';
              return out;
            }, '')}
          </select>
        </div>
        <div class="field-label">Subject</div>
        <div><input type="text" id="email-subject" placeholder="Subject..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label" id="email-body-label" style="display:none;">Body</div>
        <div id="email-body-wrap" style="display:none;"><textarea id="email-body" rows="6" placeholder="Body text (only for Custom template)..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);"></textarea></div>
        <div class="field-label" id="cta-label" style="display:none;">CTA URL</div>
        <div id="cta-url-wrap" style="display:none;"><input type="text" id="cta-url" placeholder="https://..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label" id="dual-sig-label" style="display:none;">Signature</div>
        <div id="dual-sig-wrap" style="display:none; align-items: center; gap: var(--space-2);">
          <input type="checkbox" id="dual-sig" style="margin: 0;">
          <label for="dual-sig" style="font-size: var(--size-sm); color: var(--potisse-chocolate-soft);">Use dual signature (POT · Fran + POTISSE)</label>
        </div>
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
        <button type="button" class="btn btn-primary" data-action="send">Send</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  const templateSelect = overlay.querySelector('#email-template');
  const subjectInput = overlay.querySelector('#email-subject');
  const bodyWrap = overlay.querySelector('#email-body-wrap');
  const bodyLabel = overlay.querySelector('#email-body-label');
  const bodyInput = overlay.querySelector('#email-body');
  const ctaUrlWrap = overlay.querySelector('#cta-url-wrap');
  const ctaLabel = overlay.querySelector('#cta-label');
  const dualSigWrap = overlay.querySelector('#dual-sig-wrap');
  const dualSigLabel = overlay.querySelector('#dual-sig-label');

  // Templates de Variante A que aceptan CTA opcional
  const CTA_OPTIONAL_A = ['product_availability', 'production_timing', 'address_check', 'nfc_quantity', 'delivery_delayed', 'return_confirmation'];

  function updateFields() {
    const val = templateSelect.value;
    const defs = EMAIL_TEMPLATE_DEFAULTS[val];
    if (defs && !subjectInput.dataset.edited) subjectInput.value = defs.subject || '';

    // Body editable para todos los templates (pre-cargado del template)
    bodyWrap.style.display = '';
    bodyLabel.style.display = '';
    if (defs && !bodyInput.dataset.edited) bodyInput.value = defs.body || '';

    // CTA URL visible para templates A que lo usan
    const showCta = CTA_OPTIONAL_A.includes(val);
    ctaUrlWrap.style.display = showCta ? '' : 'none';
    ctaLabel.style.display = showCta ? '' : 'none';

    // Dual signature solo para silencio_3_response
    const showDual = val === 'silencio_3_response';
    dualSigWrap.style.display = showDual ? 'flex' : 'none';
    dualSigLabel.style.display = showDual ? '' : 'none';
  }

  templateSelect.addEventListener('change', () => {
    subjectInput.dataset.edited = '';
    bodyInput.dataset.edited = '';
    updateFields();
  });
  subjectInput.addEventListener('input', () => { subjectInput.dataset.edited = '1'; });
  bodyInput.addEventListener('input', () => { bodyInput.dataset.edited = '1'; });

  updateFields();

  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.querySelector('[data-action="send"]').addEventListener('click', async () => {
    const template_id = templateSelect.value;
    const payload = {
      customer_id: Number(currentCustomerId),
      template_id
    };
    // Subject override (siempre se puede editar)
    const subj = subjectInput.value.trim();
    if (subj) payload.custom_subject = subj;
    // Body editable para todos los templates
    const body = bodyInput.value.trim();
    if (body) payload.custom_body = body;
    // CTA URL
    const ctaUrlVal = overlay.querySelector('#cta-url')?.value?.trim();
    if (ctaUrlVal) payload.cta_url = ctaUrlVal;
    // Editorial style + logo para templates telegrama
    if (EDITORIAL_TEMPLATES.includes(template_id)) {
      payload.editorial_style = true;
      payload.logo_url = POTISSE_LOGO_URL;
    }

    // Dual signature
    if (template_id === 'silencio_3_response') {
      payload.use_dual_signature = overlay.querySelector('#dual-sig').checked;
    }

    overlay.remove();
    try {
      await api.post('email-customer', payload);
      toast('Email sent.', 'success');
      await refresh();
      activeTab = 'communications';
      render();
    } catch (err) {
      toast(err.message || 'Send failed.', 'error');
    }
  });
}

async function handleMarkAlertResolved() {
  if (!activeAlertEntry) return;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true">
      <p class="modal-title">Mark alert resolved</p>
      <div class="field-grid" style="grid-template-columns: 100px 1fr;">
        <div class="field-label">Action</div>
        <div>
          <select id="alert-action">
            <option value="contact_attempted">Contacted</option>
            <option value="verbal_confirmation">Verbal confirmation</option>
            <option value="issue_detected">Issue detected</option>
          </select>
        </div>
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
        <button type="button" class="btn btn-primary" data-action="confirm">Confirm</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.querySelector('[data-action="confirm"]').addEventListener('click', async () => {
    const action = overlay.querySelector('#alert-action').value;
    overlay.remove();
    try {
      await api.post('access-alerts/resolve', { order_id: activeAlertEntry.order_id, action });
      toast('Alert updated.', 'success');
      await refresh();
    } catch (err) {
      toast(err.message || 'Failed.', 'error');
    }
  });
}

async function handleSendSilencio1() {
  const name = currentProfile.identity.first_name || 'this customer';
  const ok = await confirmModal('Send Silencio 1?', `Apply courtesy shipping to ${escapeHtml(name)}?`, 'Send', false);
  if (!ok) return;
  try {
    await api.post(`members/${currentCustomerId}/tags`, { action: 'add', tag: 'envio_cortesia_activo' });
    toast('Silencio 1 sent.', 'success');
    await refresh();
    activeTab = 'silencios';
    render();
  } catch (err) {
    toast(err.message || 'Failed.', 'error');
  }
}

async function handleEmergencySession() {
  const name = currentProfile.identity.first_name || 'this customer';
  const ok = await tripleConfirmModal('Emergency session', [
    `This will open a new tab logged in as ${escapeHtml(name)} in the Club, valid for 30 minutes.`,
    'This is a debug tool. Use only when necessary.'
  ]);
  if (!ok) return;
  try {
    const res = await fetch(`/api/admin/emergency-session?customer_id=${currentCustomerId}`, { credentials: 'include' });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `HTTP ${res.status}`);
    }
    window.open('https://www.potisse.com/pages/club', '_blank');
    toast('Debug session opened in new tab. Close it when done.', 'info');
  } catch (err) {
    toast(err.message || 'Failed to open emergency session.', 'error');
  }
}


async function handleEditIncidence(incidenceId) {
  const data = tabDataCache['incidences'];
  const inc = (data?.incidences || []).find(i => i.incidence_id === incidenceId);
  if (!inc) {
    toast('Incidence not found.', 'error');
    return;
  }
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 520px;">
      <p class="modal-title">Edit incidence</p>
      <div class="field-grid" style="grid-template-columns: 120px 1fr; gap: var(--space-3) var(--space-4);">
        <div class="field-label">Type</div>
        <div>
          <select id="inc-type" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);">
            <option value="defect" ${inc.type === 'defect' ? 'selected' : ''}>Defect</option>
            <option value="delay" ${inc.type === 'delay' ? 'selected' : ''}>Delay</option>
            <option value="lost" ${inc.type === 'lost' ? 'selected' : ''}>Lost shipment</option>
            <option value="return" ${inc.type === 'return' ? 'selected' : ''}>Return</option>
            <option value="complaint" ${inc.type === 'complaint' ? 'selected' : ''}>Complaint</option>
            <option value="silencio" ${inc.type === 'silencio' ? 'selected' : ''}>Silencio</option>
            <option value="other" ${inc.type === 'other' ? 'selected' : ''}>Other</option>
          </select>
        </div>
        <div class="field-label">Severity</div>
        <div>
          <select id="inc-severity" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);">
            <option value="low" ${inc.severity === 'low' ? 'selected' : ''}>Low</option>
            <option value="medium" ${inc.severity === 'medium' ? 'selected' : ''}>Medium</option>
            <option value="high" ${inc.severity === 'high' ? 'selected' : ''}>High</option>
            <option value="critical" ${inc.severity === 'critical' ? 'selected' : ''}>Critical</option>
          </select>
        </div>
        <div class="field-label">Title</div>
        <div><input type="text" id="inc-title" value="${escapeHtml(inc.title || '')}" placeholder="Short title..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label">Description</div>
        <div><textarea id="inc-desc" rows="3" placeholder="Details..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);">${escapeHtml(inc.description || '')}</textarea></div>
        <div class="field-label">Assigned to</div>
        <div><input type="text" id="inc-assigned" value="${escapeHtml(inc.assigned_to || '')}" placeholder="Admin name (optional)" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label">Order ID</div>
        <div><input type="text" id="inc-order" value="${escapeHtml(inc.order_id || '')}" placeholder="Optional" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label">Piece ID</div>
        <div><input type="text" id="inc-piece" value="${escapeHtml(inc.piece_id || '')}" placeholder="Optional" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
        <button type="button" class="btn btn-primary" data-action="save">Save</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.querySelector('[data-action="save"]').addEventListener('click', async () => {
    const payload = {
      type: overlay.querySelector('#inc-type').value,
      severity: overlay.querySelector('#inc-severity').value,
      title: overlay.querySelector('#inc-title').value.trim(),
      description: overlay.querySelector('#inc-desc').value.trim() || null,
      assigned_to: overlay.querySelector('#inc-assigned').value.trim() || null,
      order_id: overlay.querySelector('#inc-order').value.trim() || null,
      piece_id: overlay.querySelector('#inc-piece').value.trim() || null
    };
    if (!payload.title) {
      toast('Title is required.', 'error');
      return;
    }
    overlay.remove();
    try {
      await api.put(`members/${currentCustomerId}/incidences/${incidenceId}`, payload);
      toast('Incidence updated.', 'success');
      if (window.updateIncidenceBadge) window.updateIncidenceBadge();
      tabDataCache['incidences'] = undefined;
      refreshTabPanel('incidences');
    } catch (err) {
      toast(err.message || 'Failed to update incidence.', 'error');
    }
  });
}

async function handleRegisterIncidence() {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width: 520px;">
      <p class="modal-title">Register incidence</p>
      <div class="field-grid" style="grid-template-columns: 120px 1fr; gap: var(--space-3) var(--space-4);">
        <div class="field-label">Type</div>
        <div>
          <select id="inc-type" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);">
            <option value="defect">Defect</option>
            <option value="delay">Delay</option>
            <option value="lost">Lost shipment</option>
            <option value="return">Return</option>
            <option value="complaint">Complaint</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="field-label">Severity</div>
        <div>
          <select id="inc-severity" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
        <div class="field-label">Title</div>
        <div><input type="text" id="inc-title" placeholder="Short title..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label">Description</div>
        <div><textarea id="inc-desc" rows="3" placeholder="Details..." style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-2); border: 1px solid var(--hairline);"></textarea></div>
        <div class="field-label">Order ID</div>
        <div><input type="text" id="inc-order" placeholder="Optional" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
        <div class="field-label">Piece ID</div>
        <div><input type="text" id="inc-piece" placeholder="Optional" style="width: 100%; font-family: var(--font-body); font-size: var(--size-sm); padding: var(--space-1) var(--space-2); border: 1px solid var(--hairline);"></div>
      </div>
      <div class="modal-actions" style="margin-top: var(--space-4);">
        <button type="button" class="btn btn-secondary" data-action="cancel">Cancel</button>
        <button type="button" class="btn btn-primary" data-action="save">Save</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => overlay.remove());
  overlay.querySelector('[data-action="save"]').addEventListener('click', async () => {
    const payload = {
      type: overlay.querySelector('#inc-type').value,
      severity: overlay.querySelector('#inc-severity').value,
      title: overlay.querySelector('#inc-title').value.trim(),
      description: overlay.querySelector('#inc-desc').value.trim() || null,
      order_id: overlay.querySelector('#inc-order').value.trim() || null,
      piece_id: overlay.querySelector('#inc-piece').value.trim() || null
    };
    if (!payload.title) {
      toast('Title is required.', 'error');
      return;
    }
    overlay.remove();
    try {
      await api.post(`members/${currentCustomerId}/incidences`, payload);
      toast('Incidence registered.', 'success');
      if (window.updateIncidenceBadge) window.updateIncidenceBadge();
      tabDataCache['incidences'] = undefined;
      activeTab = 'incidences';
      render();
    } catch (err) {
      toast(err.message || 'Failed to register incidence.', 'error');
    }
  });
}

async function handleTagAction(action, tag) {
  const name = currentProfile.identity.first_name || 'this customer';
  if (action === 'remove') {
    const ok = await tripleConfirmModal('Remove tag permanently', [
      `You are about to remove "${escapeHtml(tag)}" from ${escapeHtml(name)} ${escapeHtml(currentProfile.identity.last_name || '')}.`,
      'This action cannot be undone.',
      'The tag will be removed from Shopify and the customer profile.'
    ]);
    if (!ok) return;
  } else {
    const ok = await confirmModal(`Add tag?`, `Add tag '${escapeHtml(tag)}' to ${escapeHtml(name)}?`, 'Add', false);
    if (!ok) return;
  }
  try {
    await api.post(`members/${currentCustomerId}/tags`, { action, tag });
    toast('Saved.', 'success');
    await refresh();
  } catch (err) {
    toast(err.message || 'Failed.', 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════
// WIRING
// ═══════════════════════════════════════════════════════════════════════
function wireEvents() {
  currentRoot.querySelector('#mv-back').addEventListener('click', () => {
    window.location.hash = '#/members';
  });
  const addNameBtn = currentRoot.querySelector('#mv-add-name');
  if (addNameBtn) {
    addNameBtn.addEventListener('click', () => {
      const customerId = currentProfile.customer_id || currentProfile.id;
      window.open(`https://admin.shopify.com/store/${escapeHtml(window.SHOPIFY_STORE_DOMAIN || '')}/customers/${customerId}`, '_blank');
    });
  }

  // Tab switching
  currentRoot.querySelectorAll('.member-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const newTab = tab.dataset.tab;
      if (newTab === activeTab) return;
      activeTab = newTab;
      sessionStorage.setItem(`potisse_tab_${currentCustomerId}`, activeTab);
      currentRoot.querySelectorAll('.member-tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === activeTab));
      currentRoot.querySelectorAll('.member-tab-panel').forEach((p) => p.classList.toggle('active', p.dataset.panel === activeTab));
      loadTabDataIfNeeded(activeTab);
      wireTabSpecificEvents(activeTab);
    });
  });

  // Header actions
  currentRoot.querySelector('#act-send-email')?.addEventListener('click', handleSendEmail);
  currentRoot.querySelector('#act-magic-link')?.addEventListener('click', handleSendMagicLink);
  currentRoot.querySelector('#act-mark-alert')?.addEventListener('click', handleMarkAlertResolved);
  currentRoot.querySelector('#act-silencio-1')?.addEventListener('click', handleSendSilencio1);
  currentRoot.querySelector('#act-register-incidence')?.addEventListener('click', handleRegisterIncidence);
  currentRoot.querySelector('#act-emergency-session')?.addEventListener('click', handleEmergencySession);

  // Wire events for the currently active tab
  wireTabSpecificEvents(activeTab);

  // Sync buttons (retry + details toggle only)

  // v6.9.2: boton Sync now en banner de divergencia

  const syncDetailsBtn = currentRoot.querySelector('#mv-sync-details-toggle');
  if (syncDetailsBtn) syncDetailsBtn.addEventListener('click', handleSyncDetailsToggle);

  const refreshBtn = currentRoot.querySelector('#mv-refresh-shopify');
  if (refreshBtn) refreshBtn.addEventListener('click', handleRefreshFromShopify);}
function wireTabSpecificEvents(tabId) {
  if (!currentRoot) return;

  // Inline field editing (present in overview and identity tabs)
  currentRoot.querySelectorAll('[data-field]').forEach((el) => {
    el.addEventListener('click', () => handleFieldClick(el));
  });

  // Incidences tab
  if (tabId === 'incidences') {
    currentRoot.querySelectorAll('.incidence-resolve-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const id = btn.dataset.id;
        const ok = await confirmModal('Mark resolved?', 'This incidence will be marked as resolved.', 'Resolve', false);
        if (!ok) return;
        try {
          await api.post(`members/${currentCustomerId}/incidences/${id}/resolve`, {});
          toast('Incidence resolved.', 'success');
          if (window.updateIncidenceBadge) window.updateIncidenceBadge();
          tabDataCache['incidences'] = undefined;
          refreshTabPanel('incidences');
        } catch (err) {
          toast(err.message || 'Failed.', 'error');
        }
      });
    });
    currentRoot.querySelectorAll('.incidence-edit-btn').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await handleEditIncidence(btn.dataset.id);
      });
    });
  }

  // Tags & Notes tab
  if (tabId === 'tags-notes') {
    currentRoot.querySelectorAll('.tag-remove-x').forEach((x) => {
      x.addEventListener('click', () => handleTagAction('remove', x.dataset.tag));
    });
    const addTagInput = currentRoot.querySelector('#mv-add-tag');
    if (addTagInput) {
      addTagInput.addEventListener('keydown', (e) => {
        const isEnter = e.key === 'Enter' || e.keyCode === 13 || e.which === 13;
        if (isEnter && addTagInput.value.trim()) {
          e.preventDefault();
          e.stopPropagation();
          const tag = addTagInput.value.trim();
          addTagInput.value = '';
          handleTagAction('add', tag);
        }
      });
    }
    const notesTextarea = currentRoot.querySelector('#mv-notes-free');
    const notesSaveBtn = currentRoot.querySelector('#mv-notes-save');
    if (notesTextarea && notesSaveBtn) {
      const original = currentProfile.notes_free || '';
      notesTextarea.addEventListener('input', () => {
        notesSaveBtn.style.display = notesTextarea.value !== original ? '' : 'none';
      });
      notesSaveBtn.addEventListener('click', async () => {
        const name = currentProfile.identity.first_name || 'this customer';
        const ok = await confirmModal('Save notes?', `Save notes for ${escapeHtml(name)}?`, 'Save', false);
        if (!ok) return;
        try {
          await api.post(`members/${currentCustomerId}/notes`, { notes_free: notesTextarea.value });
          toast('Saved.', 'success');
          await refresh();
        } catch (err) {
          toast(err.message || 'Save failed.', 'error');
        }
      });
    }
  }
}
