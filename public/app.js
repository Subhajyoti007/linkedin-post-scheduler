const state = {
  mode: 'live',
  oauth: null,
  posts: [],
  logs: [],
  idempotencyKey: crypto.randomUUID()
};

const els = {
  modePill: document.getElementById('mode-pill'),
  workerPill: document.getElementById('worker-pill'),
  banner: document.getElementById('global-banner'),
  connectionBadge: document.getElementById('connection-badge'),
  connectedPanel: document.getElementById('connected-panel'),
  memberName: document.getElementById('member-name'),
  memberUrn: document.getElementById('member-urn'),
  tokenExpiry: document.getElementById('token-expiry'),
  disconnectBtn: document.getElementById('disconnect-btn'),
  oauthForm: document.getElementById('oauth-form'),
  clientId: document.getElementById('client-id'),
  clientSecret: document.getElementById('client-secret'),
  secretSavedHint: document.getElementById('secret-saved-hint'),
  redirectUri: document.getElementById('redirect-uri'),
  copyRedirectBtn: document.getElementById('copy-redirect-btn'),
  connectOAuthBtn: document.getElementById('connect-oauth-btn'),
  fillDemoBtn: document.getElementById('fill-demo-btn'),
  postForm: document.getElementById('post-form'),
  postContent: document.getElementById('post-content'),
  charCounter: document.getElementById('char-counter'),
  postVisibility: document.getElementById('post-visibility'),
  scheduledAt: document.getElementById('scheduled-at'),
  tzLabel: document.getElementById('tz-label'),
  scheduleBtn: document.getElementById('schedule-btn'),
  postsList: document.getElementById('posts-list'),
  refreshPostsBtn: document.getElementById('refresh-posts-btn'),
  logsList: document.getElementById('logs-list'),
  logLevelFilter: document.getElementById('log-level-filter'),
  mockPanel: document.getElementById('mock-panel'),
  mockFaultForm: document.getElementById('mock-fault-form'),
  mockTempCount: document.getElementById('mock-temp-count'),
  mockTempStatus: document.getElementById('mock-temp-status'),
  mockPerm422Btn: document.getElementById('mock-perm-422-btn'),
  mockResetBtn: document.getElementById('mock-reset-btn'),
  mockFeedCount: document.getElementById('mock-feed-count'),
  mockStats: document.getElementById('mock-stats')
};

function showBanner(type, message) {
  els.banner.className = `banner ${type}`;
  els.banner.textContent = message;
  els.banner.classList.remove('hidden');
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text == null ? '' : String(text);
  return div.innerHTML;
}

function toDatetimeLocalValue(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function formatDurationMs(ms) {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

async function api(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status;
    err.code = data.code;
    throw err;
  }
  return data;
}

function setScheduleOffsetSeconds(offsetSec) {
  const target = new Date(Date.now() + offsetSec * 1000);
  els.scheduledAt.value = toDatetimeLocalValue(target);
}

async function loadHealth() {
  try {
    const health = await api('/api/health');
    state.mode = health.mode;
    els.modePill.textContent =
      health.mode === 'mock' ? 'Mock Sandbox Mode' : 'Live LinkedIn API';
    els.modePill.className = `pill ${health.mode === 'mock' ? 'pill-warn' : 'pill-info'}`;

    const running = health.worker?.running;
    els.workerPill.textContent = running
      ? `Worker Active (${Math.round((health.worker.pollIntervalMs || 1000) / 1000)}s poll)`
      : 'Worker Stopped';
    els.workerPill.className = `pill ${running ? 'pill-success' : 'pill-danger'}`;

    if (health.mode === 'mock') {
      els.mockPanel.classList.remove('hidden');
      els.fillDemoBtn.classList.remove('hidden');
    }
  } catch {
    els.workerPill.textContent = 'Server Offline';
    els.workerPill.className = 'pill pill-danger';
  }
}

async function loadOAuthStatus(populateInputs = false) {
  const data = await api('/api/oauth/status');
  state.oauth = data;

  const { config, connection } = data;
  if (populateInputs) {
    if (config.clientId) els.clientId.value = config.clientId;
    els.redirectUri.value =
      config.redirectUri || `${window.location.origin}/auth/linkedin/callback`;
  }

  els.secretSavedHint.classList.toggle('hidden', !config.hasClientSecret);
  els.clientSecret.placeholder = config.hasClientSecret
    ? '•••••••• (encrypted & saved)'
    : 'Enter client secret';

  els.connectOAuthBtn.disabled = !config.configured;

  if (connection.connected) {
    els.connectionBadge.textContent = connection.isExpired ? 'Token Expired' : 'Connected';
    els.connectionBadge.className = `badge ${connection.isExpired ? 'badge-failed' : 'badge-published'}`;
    els.connectedPanel.classList.remove('hidden');
    els.memberName.textContent = connection.profile.name || 'LinkedIn Member';
    els.memberUrn.textContent = connection.profile.authorUrn;
    els.tokenExpiry.textContent = `Token expires: ${formatTime(connection.expiresAt)}`;
  } else {
    els.connectionBadge.textContent = 'Not connected';
    els.connectionBadge.className = 'badge badge-neutral';
    els.connectedPanel.classList.add('hidden');
  }
}

async function loadPosts() {
  const data = await api('/api/posts');
  state.posts = data.posts || [];
  renderPosts();
}

function renderPosts() {
  if (state.posts.length === 0) {
    els.postsList.innerHTML = '<p class="empty-state">No posts scheduled yet. Create one on the left.</p>';
    return;
  }

  els.postsList.innerHTML = state.posts
    .map((post) => {
      const attemptsHtml =
        post.attempts && post.attempts.length > 0
          ? `<table class="attempts-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Outcome</th>
                  <th>HTTP</th>
                  <th>Retry Delay</th>
                  <th>Duration</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                ${post.attempts
                  .map(
                    (a) => `<tr>
                      <td>${a.attemptNumber}</td>
                      <td><code>${escapeHtml(a.outcome)}</code></td>
                      <td>${a.httpStatus ?? '—'}</td>
                      <td>${a.retryDelayMs != null ? formatDurationMs(a.retryDelayMs) : '—'}</td>
                      <td>${formatDurationMs(a.durationMs)}</td>
                      <td>${escapeHtml(a.responseUrn || a.errorMessage || 'OK')}</td>
                    </tr>`
                  )
                  .join('')}
              </tbody>
            </table>`
          : '<p class="muted small">No publish attempts yet — waiting for scheduled time.</p>';

      const canRetry = post.status === 'failed' && !post.publishedPostUrn;
      const canDelete = post.status === 'scheduled' || post.status === 'failed';
      const retryBadge =
        post.status === 'scheduled' && post.attemptCount > 0
          ? `<span class="badge badge-processing">Retry scheduled for ${escapeHtml(formatTime(post.nextAttemptAt))}</span>`
          : '';

      return `<article class="post-item">
        <div class="post-top">
          <div class="btn-row">
            <span class="badge badge-${escapeHtml(post.status)}">${escapeHtml(post.status)}</span>
            ${retryBadge}
          </div>
          <div class="btn-row">
            ${canRetry ? `<button type="button" class="btn btn-secondary btn-sm" data-action="retry" data-id="${escapeHtml(post.id)}">Retry Now</button>` : ''}
            ${canDelete ? `<button type="button" class="btn btn-ghost btn-sm" data-action="delete" data-id="${escapeHtml(post.id)}">Delete</button>` : ''}
          </div>
        </div>

        <div class="post-content">${escapeHtml(post.content)}</div>

        ${post.lastError ? `<div class="post-error"><strong>${escapeHtml(post.lastErrorCode || 'ERROR')}:</strong> ${escapeHtml(post.lastError)}</div>` : ''}

        <div class="meta-grid">
          <div><span class="meta-label">Author</span><code>${escapeHtml(post.authorUrn)}</code></div>
          <div><span class="meta-label">Scheduled For</span>${escapeHtml(formatTime(post.scheduledAt))}</div>
          <div><span class="meta-label">Attempts</span>${post.attemptCount} / ${post.maxAttempts}</div>
          <div><span class="meta-label">Published URN</span>${post.publishedPostUrn ? `<code>${escapeHtml(post.publishedPostUrn)}</code>` : '—'}</div>
        </div>

        ${attemptsHtml}
      </article>`;
    })
    .join('');
}

async function loadLogs() {
  const level = els.logLevelFilter.value;
  const query = level ? `?level=${encodeURIComponent(level)}&limit=80` : '?limit=80';
  const data = await api(`/api/logs${query}`);
  state.logs = data.logs || [];

  if (state.logs.length === 0) {
    els.logsList.innerHTML = '<p class="empty-state">No log entries yet.</p>';
    return;
  }

  els.logsList.innerHTML = state.logs
    .map(
      (l) => `<div class="log-row">
        <span class="log-time">${escapeHtml(new Date(l.createdAt).toLocaleTimeString())}</span>
        <span class="log-level-${escapeHtml(l.level)}">${escapeHtml(l.level.toUpperCase())}</span>
        <span class="log-comp">[${escapeHtml(l.component)}]</span>
        <span>${escapeHtml(l.event)}: ${escapeHtml(l.message)}</span>
      </div>`
    )
    .join('');
}

async function loadMockState() {
  if (state.mode !== 'mock') return;
  const mock = await api('/api/mock/state');
  els.mockFeedCount.textContent = `${mock.createdPosts.length} created`;
  els.mockStats.textContent = `Requests received: ${mock.postRequests.length} | Posts created: ${mock.createdPosts.length} | Remaining temp faults: ${mock.faultPlan.temporaryFailuresRemaining}`;
}

// Event Listeners
els.oauthForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('/api/oauth/credentials', {
      method: 'POST',
      body: JSON.stringify({
        clientId: els.clientId.value,
        clientSecret: els.clientSecret.value,
        redirectUri: els.redirectUri.value
      })
    });
    els.clientSecret.value = '';
    await loadOAuthStatus(false);
    showBanner('success', 'LinkedIn OAuth credentials encrypted and saved. Click "Connect with LinkedIn" next.');
  } catch (err) {
    showBanner('error', err.message);
  }
});

els.connectOAuthBtn.addEventListener('click', () => {
  window.location.href = '/auth/linkedin';
});

els.disconnectBtn.addEventListener('click', async () => {
  await api('/api/oauth/disconnect', { method: 'POST' });
  await loadOAuthStatus(false);
  showBanner('info', 'Disconnected LinkedIn account.');
});

els.copyRedirectBtn.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(els.redirectUri.value);
    showBanner('info', 'Copied Redirect URI to clipboard.');
  } catch {
    els.redirectUri.select();
  }
});

els.fillDemoBtn.addEventListener('click', () => {
  els.clientId.value = 'sandbox-client-id';
  els.clientSecret.value = 'sandbox-client-secret';
  els.redirectUri.value = `${window.location.origin}/auth/linkedin/callback`;
  showBanner('info', 'Filled Sandbox demo credentials. Click "Save Credentials" then "Connect with LinkedIn".');
});

els.postContent.addEventListener('input', () => {
  els.charCounter.textContent = `${els.postContent.value.length.toLocaleString()} / 3,000`;
});

document.querySelectorAll('.chip[data-offset-sec]').forEach((btn) => {
  btn.addEventListener('click', () => {
    setScheduleOffsetSeconds(Number(btn.dataset.offsetSec));
  });
});

els.postForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const localValue = els.scheduledAt.value;
    const scheduledIso = new Date(localValue).toISOString();

    await api('/api/posts', {
      method: 'POST',
      headers: { 'Idempotency-Key': state.idempotencyKey },
      body: JSON.stringify({
        content: els.postContent.value,
        visibility: els.postVisibility.value,
        scheduledAt: scheduledIso,
        idempotencyKey: state.idempotencyKey
      })
    });

    // Generate a fresh key for the next distinct submission
    state.idempotencyKey = crypto.randomUUID();
    els.postContent.value = '';
    els.charCounter.textContent = '0 / 3,000';
    setScheduleOffsetSeconds(60);

    await Promise.all([loadPosts(), loadLogs()]);
    showBanner('success', 'Scheduled post stored in SQLite. Background worker will publish it at the scheduled time.');
  } catch (err) {
    showBanner('error', err.message);
  }
});

els.postsList.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const { action, id } = btn.dataset;
  try {
    if (action === 'retry') {
      await api(`/api/posts/${encodeURIComponent(id)}/retry`, { method: 'POST' });
      showBanner('info', 'Post re-queued for immediate retry.');
    } else if (action === 'delete') {
      await api(`/api/posts/${encodeURIComponent(id)}`, { method: 'DELETE' });
      showBanner('info', 'Post deleted.');
    }
    await Promise.all([loadPosts(), loadLogs()]);
  } catch (err) {
    showBanner('error', err.message);
  }
});

els.refreshPostsBtn.addEventListener('click', () => Promise.all([loadPosts(), loadLogs()]));
els.logLevelFilter.addEventListener('change', loadLogs);

els.mockFaultForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  await api('/api/mock/faults', {
    method: 'POST',
    body: JSON.stringify({
      temporaryFailuresRemaining: Number(els.mockTempCount.value || 0),
      temporaryStatus: Number(els.mockTempStatus.value || 503)
    })
  });
  await loadMockState();
  showBanner('info', `Sandbox configured to fail next ${els.mockTempCount.value} publish attempt(s) with HTTP ${els.mockTempStatus.value}.`);
});

els.mockPerm422Btn.addEventListener('click', async () => {
  await api('/api/mock/faults', {
    method: 'POST',
    body: JSON.stringify({
      permanentErrorStatus: 422,
      permanentErrorMessage: 'Duplicate post rejected by LinkedIn API'
    })
  });
  await loadMockState();
  showBanner('info', 'Next publish attempt in Sandbox will return permanent HTTP 422.');
});

els.mockResetBtn.addEventListener('click', async () => {
  await api('/api/mock/faults', {
    method: 'POST',
    body: JSON.stringify({ reset: true })
  });
  await loadMockState();
  showBanner('info', 'Sandbox feed and fault queue cleared.');
});

// Boot
async function init() {
  els.tzLabel.textContent = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Local';
  setScheduleOffsetSeconds(60);

  const params = new URLSearchParams(window.location.search);
  const oauthResult = params.get('oauth');
  if (oauthResult === 'connected') {
    showBanner('success', 'LinkedIn OAuth connected! Tokens encrypted and saved.');
    window.history.replaceState({}, '', '/');
  } else if (oauthResult === 'error') {
    showBanner('error', params.get('message') || 'LinkedIn OAuth connection failed.');
    window.history.replaceState({}, '', '/');
  }

  await loadHealth();
  await Promise.all([loadOAuthStatus(true), loadPosts(), loadLogs(), loadMockState()]);

  setInterval(async () => {
    await Promise.all([loadHealth(), loadOAuthStatus(false), loadPosts(), loadLogs(), loadMockState()]);
  }, 1500);
}

init().catch((err) => showBanner('error', err.message));
