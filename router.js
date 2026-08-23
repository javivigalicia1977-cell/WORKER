const DEFAULT_TAB = 'post-curation';
const CACHE_BUST = '?v=27';

function parseRoute() {
  const hash = window.location.hash;
  const match = hash.match(/^#\/([a-z0-9-]+)(?:\/(.*))?$/);
  if (!match) return { tabName: DEFAULT_TAB, subPath: null };
  return { tabName: match[1], subPath: match[2] || null };
}

const SPECIAL_TABS = {
  'quiet-list': '/js/quiet-list.js'
};

function setActiveNavItem(tabName) {
  document.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.tab === tabName);
  });
}

async function renderTab(tabName, subPath) {
  const root = document.getElementById('tab-root');
  setActiveNavItem(tabName);

  const modulePath = SPECIAL_TABS[tabName] || `/js/tabs/${tabName}.js${CACHE_BUST}`;
  let mod;
  try {
    mod = await import(modulePath);
  } catch (err) {
    root.innerHTML = `
      <header class="tab-header">
        <h1>Tab not found</h1>
      </header>
      <div class="tab-content">
        <p class="placeholder">"${tabName}" is not a recognized tab.</p>
      </div>
    `;
    return;
  }

  mod.render(root, subPath);
}

async function handleRoute() {
  const { tabName, subPath } = parseRoute();
  await renderTab(tabName, subPath);
}

export function initRouter() {
  if (!window.location.hash) {
    window.location.hash = `#/${DEFAULT_TAB}`;
  }
  window.addEventListener('hashchange', handleRoute);
  handleRoute();
}
