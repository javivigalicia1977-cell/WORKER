// post-curation.js — v1.1 (Fase C.1)
import { timeAgo } from '/js/utils.js?v=2';

/* ═══════════════════════════════════════════════════════════════════
   FALLBACK UI helpers (migrar a /js/ui.js en C.4)
   ═══════════════════════════════════════════════════════════════════ */

function toast(msg, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;bottom:var(--space-4);right:var(--space-4);z-index:9999;display:flex;flex-direction:column;gap:var(--space-2);';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  const bg = type === 'danger' ? 'var(--danger)' : type === 'success' ? 'var(--success, #4a7c59)' : 'var(--text)';
  el.style.cssText = `background:${bg};color:#fff;padding:var(--space-3) var(--space-4);border-radius:var(--radius-sm);font-size:var(--size-sm);box-shadow:0 2px 8px rgba(0,0,0,0.15);animation:toastIn 0.2s ease;cursor:pointer;`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3000);
  el.onclick = () => el.remove();
}

function confirmModal(message, opts = {}) {
  return new Promise((resolve) => {
    const { confirmText = 'Confirm', cancelText = 'Cancel', title = 'Confirm' } = opts;
    let modal = document.getElementById('confirm-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'confirm-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }
    modal.innerHTML = `
      <div class="modal" style="max-width:400px;">
        <h2 class="modal-title">${title}</h2>
        <p class="modal-message">${message}</p>
        <div class="modal-actions" style="margin-top:var(--space-4);">
          <button class="btn btn-secondary" id="confirm-cancel">${cancelText}</button>
          <button class="btn btn-primary" id="confirm-ok">${confirmText}</button>
        </div>
      </div>
    `;
    modal.style.display = 'flex';
    const okBtn = modal.querySelector('#confirm-ok');
    const cancelBtn = modal.querySelector('#confirm-cancel');
    function cleanup() {
      modal.style.display = 'none';
      okBtn.onclick = null;
      cancelBtn.onclick = null;
    }
    okBtn.onclick = () => { cleanup(); resolve(true); };
    cancelBtn.onclick = () => { cleanup(); resolve(false); };
  });
}

/* ═══════════════════════════════════════════════════════════════════
   MODULE STATE
   ═══════════════════════════════════════════════════════════════════ */

let currentPosts = [];
let currentFilter = 'pending';
let currentViewMode = localStorage.getItem('potisse_posts_view_mode') || 'grid';
let isLoading = false;

/* ── helpers ─────────────────────────────────────── */

function getAdminKey() {
  return new URLSearchParams(window.location.search).get('admin') || '';
}

async function api(path, options = {}) {
  const res = await fetch(`/api/proxy/admin${path}`, options);
  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: 'unknown' }));
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function imgUrl(postId) {
  const key = getAdminKey();
  return `/api/proxy/admin/posts/image/${postId}${key ? '?admin=' + encodeURIComponent(key) : ''}`;
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function extractHashtags(caption) {
  if (!caption) return [];
  const matches = caption.match(/#\w+/g);
  return matches ? [...new Set(matches)] : [];
}

/* ═══════════════════════════════════════════════════════════════════
   MODALS
   ═══════════════════════════════════════════════════════════════════ */

function askPublishIgData() {
  return new Promise((resolve, reject) => {
    let modal = document.getElementById('ig-publish-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'ig-publish-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }
    modal.innerHTML = `
      <div class="modal" style="max-width:420px;">
        <h2 class="modal-title">Publish to Instagram</h2>
        <p class="modal-message">Paste the Instagram post URL, then type <strong>PUBLISHED</strong> to confirm this action is intentional.</p>
        <input type="url" id="ig-url-input" placeholder="https://instagram.com/p/..." style="width:100%;margin-top:var(--space-3);padding:var(--space-2);border:1px solid var(--border);border-radius:var(--radius-sm);font-family:inherit;font-size:var(--size-sm);">
        <input type="text" id="ig-confirm-input" placeholder="Type PUBLISHED to unlock" style="width:100%;margin-top:var(--space-2);padding:var(--space-2);border:1px solid var(--border);border-radius:var(--radius-sm);font-family:inherit;font-size:var(--size-sm);">
        <p class="totp-error" id="ig-error" style="display:none;color:var(--danger);font-size:var(--size-xs);margin-top:var(--space-2);"></p>
        <div class="modal-actions" style="margin-top:var(--space-4);">
          <button class="btn btn-secondary" id="ig-cancel">Cancel</button>
          <button class="btn btn-primary" id="ig-confirm" disabled>Publish</button>
        </div>
      </div>
    `;
    modal.style.display = 'flex';

    const urlInput = modal.querySelector('#ig-url-input');
    const confirmInput = modal.querySelector('#ig-confirm-input');
    const confirmBtn = modal.querySelector('#ig-confirm');
    const cancelBtn = modal.querySelector('#ig-cancel');
    const errorP = modal.querySelector('#ig-error');

    function checkEnable() {
      const urlOk = /^https:\/\//.test(urlInput.value.trim());
      const confirmOk = confirmInput.value.trim() === 'PUBLISHED';
      confirmBtn.disabled = !(urlOk && confirmOk);
      errorP.style.display = 'none';
    }

    urlInput.addEventListener('input', checkEnable);
    confirmInput.addEventListener('input', checkEnable);
    urlInput.focus();

    function cleanup() {
      modal.style.display = 'none';
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      urlInput.oninput = null;
      confirmInput.oninput = null;
    }

    confirmBtn.onclick = () => {
      const url = urlInput.value.trim();
      if (!/^https:\/\//.test(url) || confirmInput.value.trim() !== 'PUBLISHED') {
        errorP.textContent = 'Enter a valid URL and type PUBLISHED exactly.';
        errorP.style.display = 'block';
        return;
      }
      cleanup();
      resolve({ url, confirmed: true });
    };

    cancelBtn.onclick = () => { cleanup(); reject(new Error('cancelled')); };
  });
}

function askDiscardReason() {
  return new Promise((resolve, reject) => {
    let modal = document.getElementById('discard-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'discard-modal';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }
    modal.innerHTML = `
      <div class="modal" style="max-width:420px;">
        <h2 class="modal-title">Discard post</h2>
        <p class="modal-message">Why is this post being discarded? (visible in Timeline for audit)</p>
        <textarea id="discard-reason" rows="4" placeholder="Reason..." style="width:100%;margin-top:var(--space-3);padding:var(--space-2);border:1px solid var(--border);border-radius:var(--radius-sm);font-family:inherit;font-size:var(--size-sm);resize:vertical;"></textarea>
        <p class="totp-error" id="discard-error" style="display:none;color:var(--danger);font-size:var(--size-xs);margin-top:var(--space-2);"></p>
        <div class="modal-actions" style="margin-top:var(--space-4);">
          <button class="btn btn-secondary" id="discard-cancel">Cancel</button>
          <button class="btn btn-danger" id="discard-confirm" disabled>Discard</button>
        </div>
      </div>
    `;
    modal.style.display = 'flex';

    const textarea = modal.querySelector('#discard-reason');
    const confirmBtn = modal.querySelector('#discard-confirm');
    const cancelBtn = modal.querySelector('#discard-cancel');
    const errorP = modal.querySelector('#discard-error');

    textarea.addEventListener('input', () => {
      confirmBtn.disabled = textarea.value.trim().length < 5;
      errorP.style.display = 'none';
    });
    textarea.focus();

    function cleanup() {
      modal.style.display = 'none';
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      textarea.oninput = null;
    }

    confirmBtn.onclick = () => {
      const reason = textarea.value.trim();
      if (reason.length < 5) {
        errorP.textContent = 'Reason must be at least 5 characters.';
        errorP.style.display = 'block';
        return;
      }
      cleanup();
      resolve(reason);
    };

    cancelBtn.onclick = () => { cleanup(); reject(new Error('cancelled')); };
  });
}

function openPreviewModal(postId) {
  const post = currentPosts.find(p => p.post_id === postId);
  if (!post) return;

  let modal = document.getElementById('post-preview-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'post-preview-modal';
    modal.className = 'modal-overlay';
    document.body.appendChild(modal);
  }

  const name = post.first_name || `Customer ${post.customer_id}`;
  const submitted = post.submitted_at ? new Date(post.submitted_at) : null;
  const dateStr = submitted ? submitted.toLocaleString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'Unknown';
  const timeStr = post.submitted_at ? timeAgo(post.submitted_at) : '';
  const hashtags = extractHashtags(post.caption);

  modal.innerHTML = `
    <div class="modal" style="max-width:900px;width:90vw;max-height:90vh;display:flex;flex-direction:column;overflow:hidden;">
      <div style="display:flex;flex:1;overflow:hidden;min-height:0;">
        <div style="flex:1;display:flex;align-items:center;justify-content:center;background:#000;min-height:0;">
          <img src="${imgUrl(postId)}" style="max-width:100%;max-height:80vh;object-fit:contain;" alt="Preview" onerror="this.style.display='none';this.parentElement.innerHTML='<div style=color:#fff;padding:var(--space-8)>Image unavailable</div>'">
        </div>
        <div style="width:320px;padding:var(--space-4);display:flex;flex-direction:column;overflow-y:auto;border-left:1px solid var(--border);flex-shrink:0;">
          <div style="margin-bottom:var(--space-3);">
            <a href="#/members/${post.customer_id}" target="_blank" style="font-weight:600;color:var(--primary);text-decoration:none;font-size:var(--size-base);">${escapeHtml(name)}</a>
            <div style="font-size:var(--size-xs);color:var(--muted);margin-top:var(--space-1);">${dateStr}${timeStr ? ' (' + timeStr + ')' : ''}</div>
          </div>
          ${post.caption ? `<p style="font-style:italic;font-size:var(--size-sm);color:var(--text);line-height:1.5;margin:0;">"${escapeHtml(post.caption)}"</p>` : ''}
          ${hashtags.length ? `<div style="display:flex;flex-wrap:wrap;gap:var(--space-1);margin-top:var(--space-2);">${hashtags.map(h => `<span style="background:var(--bg-2);padding:2px 8px;border-radius:var(--radius-sm);font-size:var(--size-xs);color:var(--primary);">${escapeHtml(h)}</span>`).join('')}</div>` : ''}
          <div style="margin-top:auto;padding-top:var(--space-4);display:flex;flex-direction:column;gap:var(--space-2);">
            ${post.caption ? `<button class="btn btn-sm btn-secondary" id="preview-copy-caption">Copy caption</button>` : ''}
            <div style="display:flex;gap:var(--space-2);flex-wrap:wrap;">
              <button class="btn btn-sm btn-primary" data-action="keep" data-id="${postId}">Keep</button>
              <button class="btn btn-sm btn-secondary" data-action="publish-ig" data-id="${postId}">Publish IG</button>
              <button class="btn btn-sm btn-danger" data-action="discard" data-id="${postId}">Discard</button>
            </div>
          </div>
        </div>
      </div>
      <button id="preview-close" style="position:absolute;top:var(--space-3);right:var(--space-3);background:rgba(0,0,0,0.5);color:#fff;border:none;width:32px;height:32px;border-radius:50%;cursor:pointer;font-size:18px;line-height:1;">&times;</button>
    </div>
  `;
  modal.style.display = 'flex';

  // Copy caption
  const copyBtn = modal.querySelector('#preview-copy-caption');
  if (copyBtn) {
    copyBtn.onclick = () => {
      navigator.clipboard.writeText(post.caption).then(() => toast('Caption copied.')).catch(() => toast('Failed to copy caption.', 'danger'));
    };
  }

  // Action buttons inside modal
  modal.querySelectorAll('button[data-action]').forEach(btn => {
    btn.onclick = () => handleAction(btn.dataset.action, postId, post);
  });

  // Close handlers
  const closeBtn = modal.querySelector('#preview-close');
  function close() { modal.style.display = 'none'; }
  closeBtn.onclick = close;
  modal.onclick = (e) => { if (e.target === modal) close(); };
  const escHandler = (e) => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escHandler); } };
  document.addEventListener('keydown', escHandler);
}

function closePreviewModal() {
  const modal = document.getElementById('post-preview-modal');
  if (modal) modal.style.display = 'none';
}

/* ═══════════════════════════════════════════════════════════════════
   RENDERING
   ═══════════════════════════════════════════════════════════════════ */

function postCardGrid(p) {
  const name = p.first_name || `Customer ${p.customer_id}`;
  const time = p.submitted_at ? timeAgo(p.submitted_at) : (p.retracted_at ? timeAgo(p.retracted_at) : '');
  const statusLabel = p.status === 'retracted' ? `<span class="badge badge-warn" style="margin-left:var(--space-2);">Retracted · ${p.hours_since_retract}h left</span>` : '';
  return `
    <div class="card" data-post-id="${p.post_id}">
      <div class="thumb" style="background:#f0eeeb;position:relative;overflow:hidden;cursor:pointer;">
        <img src="${imgUrl(p.post_id)}" alt="Post image" loading="lazy"
             style="width:100%;height:180px;object-fit:cover;display:block;"
             onerror="this.style.display='none';this.parentElement.innerHTML='<div style=\'display:flex;align-items:center;justify-content:center;height:180px;color:var(--text-muted);font-size:var(--size-sm);\'>Image unavailable</div>';">
      </div>
      <div style="padding:var(--space-3);">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div class="card-title" style="cursor:pointer;">${escapeHtml(name)}</div>
          ${statusLabel}
        </div>
        <div class="card-meta">${time}</div>
        ${p.caption ? `<p style="font-style:italic;font-size:var(--size-sm);margin-top:var(--space-2);color:var(--text-muted);max-height:3.2em;overflow:hidden;">"${escapeHtml(p.caption)}"</p>` : ''}
        <div style="display:flex;gap:var(--space-2);margin-top:var(--space-3);flex-wrap:wrap;">
          <button type="button" class="btn btn-sm btn-primary" data-action="keep" data-id="${p.post_id}">Keep</button>
          <button type="button" class="btn btn-sm btn-secondary" data-action="publish-ig" data-id="${p.post_id}">Publish IG</button>
          <button type="button" class="btn btn-sm btn-danger" data-action="discard" data-id="${p.post_id}">Discard</button>
        </div>
      </div>
    </div>
  `;
}

function postCardList(p) {
  const name = p.first_name || `Customer ${p.customer_id}`;
  const time = p.submitted_at ? timeAgo(p.submitted_at) : (p.retracted_at ? timeAgo(p.retracted_at) : '');
  const statusLabel = p.status === 'retracted' ? `<span class="badge badge-warn" style="margin-left:var(--space-2);">Retracted · ${p.hours_since_retract}h left</span>` : '';
  return `
    <div class="card post-list-row" data-post-id="${p.post_id}" style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-3);cursor:pointer;">
      <div style="width:80px;height:80px;flex-shrink:0;background:#f0eeeb;border-radius:var(--radius-sm);overflow:hidden;">
        <img src="${imgUrl(p.post_id)}" alt="" loading="lazy"
             style="width:100%;height:100%;object-fit:cover;display:block;"
             onerror="this.style.display='none';">
      </div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;">
          <span style="font-weight:600;font-size:var(--size-sm);color:var(--text);">${escapeHtml(name)}</span>
          ${statusLabel}
        </div>
        <div class="card-meta" style="margin-top:2px;">${time}</div>
        ${p.caption ? `<p style="font-style:italic;font-size:var(--size-xs);color:var(--text-muted);margin-top:var(--space-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">"${escapeHtml(p.caption)}"</p>` : ''}
      </div>
      <div style="display:flex;gap:var(--space-2);flex-shrink:0;flex-wrap:wrap;">
        <button type="button" class="btn btn-sm btn-primary" data-action="keep" data-id="${p.post_id}">Keep</button>
        <button type="button" class="btn btn-sm btn-secondary" data-action="publish-ig" data-id="${p.post_id}">Publish IG</button>
        <button type="button" class="btn btn-sm btn-danger" data-action="discard" data-id="${p.post_id}">Discard</button>
      </div>
    </div>
  `;
}

/* ═══════════════════════════════════════════════════════════════════
   STATE & ACTIONS
   ═══════════════════════════════════════════════════════════════════ */

async function loadPosts() {
  const grid = document.getElementById('post-grid');
  const status = document.getElementById('post-status');
  if (!grid) return;

  isLoading = true;
  if (status) { status.textContent = 'Loading…'; status.style.display = 'block'; }
  grid.innerHTML = '';
  currentPosts = [];

  try {
    let posts = [];
    if (currentFilter === 'pending' || currentFilter === 'all') {
      const res = await api('/posts/pending');
      posts = posts.concat(res.posts || []);
    }
    if (currentFilter === 'retracted' || currentFilter === 'all') {
      const res = await api('/posts/retracted');
      posts = posts.concat(res.posts || []);
    }
    if (currentFilter === 'all') {
      const seen = new Set();
      posts = posts.filter(p => { if (seen.has(p.post_id)) return false; seen.add(p.post_id); return true; });
      posts.sort((a, b) => new Date(b.submitted_at || b.retracted_at) - new Date(a.submitted_at || a.retracted_at));
    }

    currentPosts = posts;

    const pendingRes = await api('/posts/pending').catch(() => ({ posts: [] }));
    const retractedRes = await api('/posts/retracted').catch(() => ({ posts: [] }));
    updatePillCounts(pendingRes.posts?.length || 0, retractedRes.posts?.length || 0);

    if (posts.length === 0) {
      grid.innerHTML = `
        <div style="grid-column:1/-1;text-align:center;padding:var(--space-8);color:var(--muted);">
          <div style="font-size:3em;opacity:0.3;margin-bottom:var(--space-3);">◯</div>
          <h3 style="margin:0;font-weight:500;color:var(--text);">No moments to curate.</h3>
          <p style="margin-top:var(--space-2);font-size:var(--size-sm);">New posts will appear here when members share.</p>
        </div>
      `;
    } else {
      const renderer = currentViewMode === 'list' ? postCardList : postCardGrid;
      grid.innerHTML = posts.map(renderer).join('');
    }

    if (status) status.style.display = 'none';
  } catch (err) {
    console.error('[PostCuration] load error:', err);
    if (status) { status.textContent = 'Error loading posts. Retry?'; status.style.display = 'block'; }
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--danger);padding:var(--space-8);">Failed to load posts.</div>`;
  } finally {
    isLoading = false;
  }
}

function updatePillCounts(pendingCount, retractedCount) {
  const pills = document.querySelectorAll('.filter-pill');
  pills.forEach(pill => {
    const text = pill.textContent.toLowerCase();
    if (text.includes('pending')) pill.textContent = `Pending (${pendingCount})`;
    if (text.includes('retracted')) pill.textContent = `Retracted (${retractedCount})`;
  });
}

async function handleAction(action, postId, post = null) {
  if (isLoading) return;
  const btn = document.querySelector(`button[data-action="${action}"][data-id="${postId}"]`);
  if (btn) btn.disabled = true;

  try {
    let body = { post_id: postId, action };

    if (action === 'keep') {
      const ok = await confirmModal('Keep this post for later?', { confirmText: 'Keep', cancelText: 'Cancel', title: 'Keep post' });
      if (!ok) { if (btn) btn.disabled = false; return; }
    }

    if (action === 'publish-ig') {
      const ok1 = await confirmModal(
        'Have you already published this post on Instagram?',
        { confirmText: 'Yes, I published it', cancelText: 'Not yet', title: 'Confirm publication' }
      );
      if (!ok1) { if (btn) btn.disabled = false; return; }
      const igData = await askPublishIgData();
      if (!igData) { if (btn) btn.disabled = false; return; }
      body.ig_post_url = igData.url;
    }

    if (action === 'discard') {
      const reason = await askDiscardReason();
      if (!reason) { if (btn) btn.disabled = false; return; }
      body.reason = reason;
    }

    await api('/post/curate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    toast(action === 'keep' ? 'Post kept.' : action === 'publish-ig' ? 'Post marked as published.' : 'Post discarded.');
    await loadPosts();
    closePreviewModal();
  } catch (err) {
    if (err.message === 'cancelled') { /* user cancelled modal */ }
    else {
      console.error('[PostCuration] action error:', err);
      toast('Action failed: ' + err.message, 'danger');
    }
    if (btn) btn.disabled = false;
  }
}

/* ═══════════════════════════════════════════════════════════════════
   MAIN RENDER
   ═══════════════════════════════════════════════════════════════════ */

export function render(root) {
  // Inject styles for list view and toast animation
  if (!document.getElementById('post-curation-styles')) {
    const style = document.createElement('style');
    style.id = 'post-curation-styles';
    style.textContent = `
      .posts-view-list { display: flex; flex-direction: column; gap: var(--space-2); }
      .posts-view-list .card { margin: 0; }
      .posts-view-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: var(--space-3); }
      .view-toggle { display: flex; gap: 2px; margin-left: auto; }
      .view-toggle-btn { background: var(--bg-2); border: 1px solid var(--border); padding: var(--space-1) var(--space-2); cursor: pointer; font-size: var(--size-sm); line-height: 1; }
      .view-toggle-btn.active { background: var(--primary); color: #fff; border-color: var(--primary); }
      .view-toggle-btn:first-child { border-radius: var(--radius-sm) 0 0 var(--radius-sm); }
      .view-toggle-btn:last-child { border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
      @keyframes toastIn { from { transform: translateY(10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
    `;
    document.head.appendChild(style);
  }

  root.innerHTML = `
    <header class="tab-header">
      <h1>Post curation</h1>
      <p class="tab-subtitle">Moments awaiting their reply.</p>
    </header>
    <div class="tab-content">
      <div class="toolbar" style="display:flex;align-items:center;gap:var(--space-2);flex-wrap:wrap;">
        <div class="toolbar-filters">
          <button type="button" class="filter-pill active" data-filter="pending">Pending (…)</button>
          <button type="button" class="filter-pill" data-filter="retracted">Retracted (…)</button>
          <button type="button" class="filter-pill" data-filter="all">All</button>
        </div>
        <div class="view-toggle">
          <button type="button" class="view-toggle-btn ${currentViewMode === 'grid' ? 'active' : ''}" data-view="grid" title="Grid view">⊞</button>
          <button type="button" class="view-toggle-btn ${currentViewMode === 'list' ? 'active' : ''}" data-view="list" title="List view">≡</button>
        </div>
        <button type="button" class="btn btn-sm btn-secondary" id="post-refresh-btn">Refresh</button>
      </div>
      <div id="post-status" style="display:none;padding:var(--space-4);text-align:center;color:var(--text-muted);"></div>
      <div class="${currentViewMode === 'list' ? 'posts-view-list' : 'posts-view-grid'}" id="post-grid">
        <div style="grid-column:1/-1;text-align:center;color:var(--text-muted);padding:var(--space-8);">Loading…</div>
      </div>
    </div>
  `;

  // Filter clicks
  root.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      root.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.dataset.filter;
      loadPosts();
    });
  });

  // View toggle
  root.querySelectorAll('.view-toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      root.querySelectorAll('.view-toggle-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentViewMode = btn.dataset.view;
      localStorage.setItem('potisse_posts_view_mode', currentViewMode);
      const grid = document.getElementById('post-grid');
      if (grid) {
        grid.className = currentViewMode === 'list' ? 'posts-view-list' : 'posts-view-grid';
      }
      loadPosts();
    });
  });

  // Refresh button
  const refreshBtn = root.querySelector('#post-refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadPosts);

  // Card click delegation (preview vs action)
  const grid = root.querySelector('#post-grid');
  grid.addEventListener('click', (e) => {
    const actionBtn = e.target.closest('button[data-action]');
    if (actionBtn) {
      handleAction(actionBtn.dataset.action, actionBtn.dataset.id);
      return;
    }
    const card = e.target.closest('[data-post-id]');
    if (card) {
      openPreviewModal(card.dataset.postId);
    }
  });

  loadPosts();
}
