import { initRouter } from '/js/router.js';

initRouter();

/* ═══════════════════════════════════════════════════════════════════
   FASE A — TOTP Admin (fetch interceptor + verification modal)
   ═══════════════════════════════════════════════════════════════════ */

// Helper: set X-TOTP-Code header safely (works with plain object OR Headers)
function setTOTPHeader(options, code) {
  if (!options.headers) {
    options.headers = {};
  }
  if (options.headers instanceof Headers) {
    options.headers.set('X-TOTP-Code', code);
  } else {
    options.headers['X-TOTP-Code'] = code;
  }
}

// Monkey-patch fetch para interceptar TOTP en llamadas al proxy admin
const _originalFetch = window.fetch;
window.fetch = async function(url, options = {}) {
  if (typeof url === 'string' && url.includes('/api/proxy/admin/')) {
    // Hallazgo 5: strip admin= from URL and send as X-Admin-Key header
    if (url.includes('?admin=') || url.includes('&admin=')) {
      const urlObj = new URL(url, window.location.origin);
      const adminKey = urlObj.searchParams.get('admin');
      if (adminKey) {
        urlObj.searchParams.delete('admin');
        url = urlObj.toString();
        if (!options.headers) options.headers = {};
        if (options.headers instanceof Headers) {
          options.headers.set('X-Admin-Key', adminKey);
        } else {
          options.headers['X-Admin-Key'] = adminKey;
        }
      }
    }
    // FIX B.2: usar regex en vez de includes() con wildcards literales
    const criticalPattern = /api\/proxy\/admin\/(nfc-card|emergency-session|system\/domain-ssl)/;
    const isCritical = criticalPattern.test(url);

    if (isCritical) {
      const code = await window.requestTOTPCode(true);
      setTOTPHeader(options, code);
    }

    let res = await _originalFetch(url, options);
    let cloned = res.clone();
    let data = await cloned.json().catch(() => null);

    if (data && data.error === 'totp_required') {
      const code = await window.requestTOTPCode(data.critical || isCritical);
      setTOTPHeader(options, code);
      res = await _originalFetch(url, options);
    }

    return res;
  }
  return _originalFetch(url, options);
};

// Modal TOTP — Promise que se resuelve con el código de 6 dígitos
window.requestTOTPCode = function(critical = false) {
  return new Promise((resolve, reject) => {
    let modal = document.getElementById('totp-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'totp-modal';
      modal.className = 'modal-overlay';
      modal.innerHTML = `
        <div class="modal totp-modal">
          <h2 class="modal-title">${critical ? 'Critical action' : 'Session expired'}</h2>
          <p class="modal-message">${critical ? 'This action always requires a TOTP code, even inside an active session.' : 'Your TOTP session has expired. Enter the 6-digit code from your authenticator.'}</p>
          <div class="totp-inputs">
            <input type="text" maxlength="6" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code" placeholder="000000" class="totp-input">
          </div>
          <p class="totp-error" style="display:none;color:var(--danger);font-size:var(--size-xs);margin-top:var(--space-2);"></p>
          <div class="modal-actions">
            <button class="btn btn-secondary" id="totp-cancel">Cancel</button>
            <button class="btn btn-primary" id="totp-confirm">Confirm</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    const input = modal.querySelector('.totp-input');
    const errorP = modal.querySelector('.totp-error');
    const confirmBtn = modal.querySelector('#totp-confirm');
    const cancelBtn = modal.querySelector('#totp-cancel');

    input.value = '';
    errorP.style.display = 'none';
    modal.style.display = 'flex';
    input.focus();

    function cleanup() {
      modal.style.display = 'none';
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      input.onkeydown = null;
    }

    confirmBtn.onclick = () => {
      const code = input.value.trim().replace(/\s/g, '');
      if (!/^\d{6}$/.test(code)) {
        errorP.textContent = 'Enter 6 digits';
        errorP.style.display = 'block';
        input.focus();
        return;
      }
      cleanup();
      resolve(code);
    };

    cancelBtn.onclick = () => {
      cleanup();
      reject(new Error('TOTP cancelled'));
    };

    input.onkeydown = (e) => {
      if (e.key === 'Enter') confirmBtn.click();
      if (e.key === 'Escape') cancelBtn.click();
    };
  });
};

/* ── Sidebar incidence badge ─────────────────────── */
async function updateIncidenceBadge() {
  const badge = document.getElementById('inc-badge');
  if (!badge) return;
  try {
    const res = await fetch('/api/proxy/admin/incidences/stats');
    if (!res.ok) return;
    const data = await res.json();
    const total = data.open || 0;
    const critical = data.critical || 0;
    if (total === 0) {
      badge.classList.remove('visible', 'critical');
      badge.textContent = '';
      return;
    }
    badge.textContent = '(' + (total > 99 ? '99+' : String(total)) + ')';
    badge.classList.add('visible');
    badge.classList.toggle('critical', critical > 0);
  } catch (e) {
    console.error('[Badge] error:', e);
  }
}

updateIncidenceBadge();
setInterval(updateIncidenceBadge, 30000);
window.addEventListener('hashchange', updateIncidenceBadge);
window.updateIncidenceBadge = updateIncidenceBadge;
