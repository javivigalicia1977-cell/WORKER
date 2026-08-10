// post-curation.js — v1.0-real (Fase C.1)
import { timeAgo } from '/js/utils.js';

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

/* ── modal for Publish IG ────────────────────────── */

function askIgUrl() {
  return new Promise((resolve, reject) => {
    let modal = document.getElementById('ig-url-modal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'ig-url-modal';
      modal.className = 'modal-overlay';
      modal.innerHTML = `
        <div class="modal" style="max-width:420px;">
          <h2 class="modal-title">Publish to Instagram</h2>
          <p class="modal-message">Paste the Instagram post URL.</p>
          <input type="url" class="totp-input" id="ig-url-input" placeholder="https://instagram.com/p/..." style="width:100%;margin-top:var(--space-3);">
          <p class="totp-error" id="ig-url-error" style="display:none;color:var(--danger);font-size:var(--size-xs);margin-top:var(--space-2);"></p>
          <div class="modal-actions" style="margin-top:var(--space-4);">
            <button class="btn btn-secondary" id="ig-url-cancel">Cancel</button>
            <button class="btn btn-primary" id="ig-url-confirm">Publish</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    const input = modal.querySelector('#ig-url-input');
    const errorP = modal.querySelector('#ig-url-error');
    const confirmBtn = modal.querySelector('#ig-url-confirm');
    const cancelBtn = modal.querySelector('#ig-url-cancel');

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
      const url = input.value.trim();
      if (!url || !/^https?:\/\/.+/.test(url)) {
        errorP.textContent = 'Enter a valid URL';
        errorP.style.display = 'block';
        input.focus();
        return;
      }
      cleanup();
      resolve(url);
    };

    cancelBtn.onclick = () => { cleanup(); reject(new Error('cancelled')); };
    input.onkeydown = (e) => { if (e.key === 'Enter') confirmBtn.click(); if (e.key === 'Escape') cancelBtn.click(); };
  });
}

/* ── rendering ───────────────────────────────────── */

function postCard(p) {
  const name = p.first_name || `Customer ${p.customer_id}`;
  const time = p.submitted_at ? timeAgo(p.submitted_at) : (p.retracted_at ? timeAgo(p.retracted_at) : '');
  const statusLabel = p.status === 'retracted' ? `<span class="badge badge-warn" style="margin-left:var(--space-2);">Retracted · ${p.hours_since_retract}h left</span>` : '';
  return `
    <div class="card" data-post-id="${p.post_id}">
      <div class="thumb" style="background:#f0eeeb;position:relative;overflow:hidden;">
        <img src="${imgUrl(p.post_id)}" alt="Post image" loading="lazy"
             style="width:100%;height:180px;object-fit:cover;display:block;"
             onerror="this.style.display='none';this.parentElement.innerHTML='<div style=\'display:flex;align-items:center;justify-content:center;height:180px;color:var(--text-muted);font-size:var(--size-sm);\'>Image unavailable</div>';">
      </div>
      <div style="padding:var(--space-3);">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <div class="card-title">${name}</div>
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

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ── state & actions ─────────────────────────────── */

let currentFilter = 'pending';
let isLoading = false;

async function loadPosts() {
  const grid = document.getElementById('post-grid');
  const status = document.getElementById('post-status');
  if (!grid) return;

  isLoading = true;
  if (status) { status.textContent = 'Loading…'; status.style.display = 'block'; }
  grid.innerHTML = '';

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

    const pendingRes = await api('/posts/pending').catch(() => ({ posts: [] }));
    const retractedRes = await api('/posts/retracted').catch(() => ({ posts: [] }));
    updatePillCounts(pendingRes.posts?.length || 0, retractedRes.posts?.length || 0);

    if (posts.length === 0) {
      grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text-muted);padding:var(--space-8);">No posts in this view.</div>`;
    } else {
      grid.innerHTML = posts.map(postCard).join('');
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

async function handleAction(action, postId) {
  if (isLoading) return;
  const btn = document.querySelector(`button[data-action="${action}"][data-id="${postId}"]`);
  if (btn) btn.disabled = true;

  try {
    let body = { post_id: postId, action };

    if (action === 'publish_ig') {
      const igUrl = await askIgUrl();
      body.ig_post_url = igUrl;
    }

    if (action === 'discard') {
      if (!confirm('Discard this post? The customer will be notified.')) {
        if (btn) btn.disabled = false;
        return;
      }
    }

    await api('/post/curate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    await loadPosts();
  } catch (err) {
    if (err.message === 'cancelled') { /* user cancelled modal */ }
    else {
      console.error('[PostCuration] action error:', err);
      alert('Action failed: ' + err.message);
    }
    if (btn) btn.disabled = false;
  }
}

/* ── main render ─────────────────────────────────── */

export function render(root) {
  root.innerHTML = `
    <header class="tab-header">
      <h1>Post curation</h1>
      <p class="tab-subtitle">Moments awaiting their reply.</p>
    </header>
    <div class="tab-content">
      <div class="toolbar">
        <div class="toolbar-filters">
          <button type="button" class="filter-pill active" data-filter="pending">Pending (…)</button>
          <button type="button" class="filter-pill" data-filter="retracted">Retracted (…)</button>
          <button type="button" class="filter-pill" data-filter="all">All</button>
        </div>
        <button type="button" class="btn btn-sm btn-secondary" id="post-refresh-btn">Refresh</button>
      </div>
      <div id="post-status" style="display:none;padding:var(--space-4);text-align:center;color:var(--text-muted);"></div>
      <div class="card-grid" id="post-grid">
        <div style="grid-column:1/-1;text-align:center;color:var(--text-muted);padding:var(--space-8);">Loading…</div>
      </div>
    </div>
  `;

  root.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      root.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.dataset.filter;
      loadPosts();
    });
  });

  const refreshBtn = root.querySelector('#post-refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', loadPosts);

  const grid = root.querySelector('#post-grid');
  grid.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const postId = btn.dataset.id;
    handleAction(action, postId);
  });

  loadPosts();
}
