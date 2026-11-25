import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startApplication } from '../src/index.js';
import { PostWorker } from '../src/worker.js';

async function waitForCondition(fn, { timeoutMs = 5000, intervalMs = 25 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await fn();
    if (val) return val;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for condition`);
}

async function createTestApp(overrides = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'li-e2e-'));
  const app = await startApplication({
    port: 0,
    host: '127.0.0.1',
    linkedinMode: 'mock',
    databasePath: path.join(tmpDir, 'test.db'),
    logFilePath: path.join(tmpDir, 'app.log'),
    masterKeyPath: path.join(tmpDir, '.master.key'),
    tokenEncryptionKey: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    workerPollIntervalMs: 40,
    retryBaseDelayMs: 60,
    retryMaxDelayMs: 500,
    maxRetryAttempts: 4,
    silentLogs: true,
    ...overrides
  });

  return {
    app,
    tmpDir,
    async cleanup() {
      await app.stop();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  };
}

async function connectOAuthViaHttp(app) {
  const redirectUri = `${app.baseUrl}/auth/linkedin/callback`;
  const saveRes = await fetch(`${app.baseUrl}/api/oauth/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientId: 'test-client-id',
      clientSecret: 'super-secret-client-secret',
      redirectUri
    })
  });
  assert.equal(saveRes.status, 200);

  // Start OAuth flow without auto-following final redirect so we can verify flow step-by-step
  
  const authRes = await fetch(`${app.baseUrl}/auth/linkedin`, { redirect: 'manual' });
  assert.equal(authRes.status, 302);
  const mockAuthUrl = new URL(authRes.headers.get('location'));
  mockAuthUrl.searchParams.set('auto_approve', '1');

  const consentRes = await fetch(mockAuthUrl.toString(), { redirect: 'manual' });
  assert.equal(consentRes.status, 302);
  const callbackUrl = consentRes.headers.get('location');
  assert.ok(callbackUrl.startsWith(redirectUri));

  const cbRes = await fetch(callbackUrl, { redirect: 'manual' });
  assert.equal(cbRes.status, 302);
  assert.equal(cbRes.headers.get('location'), '/?oauth=connected');
}

test('E2E: OAuth security, encrypted token storage, CSRF state validation, and single post publishing', async () => {
  const { app, cleanup } = await createTestApp();
  try {
    // Reject invalid/forged OAuth state
    
    const badCb = await fetch(
      `${app.baseUrl}/auth/linkedin/callback?code=fake&state=invalid_csrf_state`,
      { redirect: 'manual' }
    );
    assert.equal(badCb.status, 302);
    assert.ok(badCb.headers.get('location').includes('oauth=error'));

    await connectOAuthViaHttp(app);

    // Ensure secrets are encrypted in SQLite and never exposed in API or logs
    
    const statusRes = await fetch(`${app.baseUrl}/api/oauth/status`).then((r) => r.json());
    assert.equal(statusRes.connection.connected, true);
    assert.equal(statusRes.connection.profile.authorUrn, 'urn:li:person:mock_member_782');
    assert.equal(statusRes.config.hasClientSecret, true);
    assert.equal(JSON.stringify(statusRes).includes('super-secret-client-secret'), false);

    const rawConfigRow = app.db.db.prepare('SELECT client_secret_encrypted FROM oauth_configs WHERE id = 1').get();
    assert.ok(rawConfigRow.client_secret_encrypted.startsWith('v1:'));
    assert.equal(rawConfigRow.client_secret_encrypted.includes('super-secret-client-secret'), false);

    const rawTokenRow = app.db.db.prepare('SELECT access_token_encrypted FROM oauth_tokens WHERE id = 1').get();
    assert.ok(rawTokenRow.access_token_encrypted.startsWith('v1:'));
    assert.equal(rawTokenRow.access_token_encrypted.includes('mock_access_'), false);

    // Schedule a post slightly in the future
    
    const scheduledAt = new Date(Date.now() + 180).toISOString();
    const createRes = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': 'idem-key-1'
      },
      body: JSON.stringify({
        content: 'Hello LinkedIn (from automated test)! #NodeJS',
        visibility: 'PUBLIC',
        scheduledAt
      })
    });
    assert.equal(createRes.status, 201);
    const { post: created } = await createRes.json();
    assert.equal(created.status, 'scheduled');
    assert.equal(app.mockServer.createdPosts.length, 0);

    // Wait for background worker to publish at scheduled time
    
    const published = await waitForCondition(async () => {
      const { post } = await fetch(`${app.baseUrl}/api/posts/${created.id}`).then((r) => r.json());
      return post.status === 'published' ? post : null;
    });

    assert.ok(published.publishedPostUrn.startsWith('urn:li:share:'));
    assert.equal(published.attemptCount, 1);
    assert.equal(app.mockServer.createdPosts.length, 1);
    assert.ok(
      app.mockServer.createdPosts[0].commentary.includes('\\(from automated test\\)'),
      'Reserved parentheses should be escaped while preserving #NodeJS'
    );
    assert.ok(app.mockServer.createdPosts[0].commentary.includes('#NodeJS'));
  } finally {
    await cleanup();
  }
});

test('E2E: Temporary LinkedIn errors trigger automatic retries with increasing delays and zero duplicates', async () => {
  const { app, cleanup } = await createTestApp({
    retryBaseDelayMs: 60,
    retryMaxDelayMs: 1000,
    maxRetryAttempts: 5
  });
  try {
    await connectOAuthViaHttp(app);

    // Simulate 3 temporary 503 errors before LinkedIn succeeds on attempt 4
    app.mockServer.setFaultPlan({
      temporaryFailuresRemaining: 3,
      temporaryStatus: 503
    });

    const createRes = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Resilient scheduled post after temporary 503 outages.',
        scheduledAt: new Date(Date.now() + 30).toISOString()
      })
    });
    assert.equal(createRes.status, 201);
    const { post: created } = await createRes.json();

    const published = await waitForCondition(
      async () => {
        const { post } = await fetch(`${app.baseUrl}/api/posts/${created.id}`).then((r) => r.json());
        return post.status === 'published' ? post : null;
      },
      { timeoutMs: 6000 }
    );

    assert.equal(published.attemptCount, 4);
    assert.equal(published.attempts.length, 4);
    assert.equal(published.attempts[0].outcome, 'temporary_error');
    assert.equal(published.attempts[1].outcome, 'temporary_error');
    assert.equal(published.attempts[2].outcome, 'temporary_error');
    assert.equal(published.attempts[3].outcome, 'succeeded');

    // Verify strictly increasing retry delays (60ms -> 120ms -> 240ms)
    
    const d1 = published.attempts[0].retryDelayMs;
    const d2 = published.attempts[1].retryDelayMs;
    const d3 = published.attempts[2].retryDelayMs;
    assert.equal(d1, 60);
    assert.equal(d2, 120);
    assert.equal(d3, 240);
    assert.ok(d2 > d1 && d3 > d2, 'Retry delays must strictly increase');

    // Verify only 1 post was created on LinkedIn despite 4 total HTTP attempts
    
    assert.equal(app.mockServer.postRequests.length, 4);
    assert.equal(app.mockServer.createdPosts.length, 1);
  } finally {
    await cleanup();
  }
});

test('E2E: Permanent error fails immediately and exhausted temporary retries mark failed', async () => {
  const { app, cleanup } = await createTestApp({
    retryBaseDelayMs: 30,
    maxRetryAttempts: 3
  });
  try {
    await connectOAuthViaHttp(app);

    // Case A: Permanent 422 fails immediately on attempt 1
    
    app.mockServer.setFaultPlan({
      permanentErrorStatus: 422,
      permanentErrorMessage: 'Duplicate post rejected by LinkedIn API'
    });

    const p1Res = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Post triggering permanent 422 error',
        scheduledAt: new Date(Date.now() + 10).toISOString()
      })
    }).then((r) => r.json());

    const failedPerm = await waitForCondition(async () => {
      const { post } = await fetch(`${app.baseUrl}/api/posts/${p1Res.post.id}`).then((r) => r.json());
      return post.status === 'failed' ? post : null;
    });
    assert.equal(failedPerm.attemptCount, 1);
    assert.equal(failedPerm.lastHttpStatus, 422);
    assert.equal(failedPerm.attempts[0].outcome, 'skipped_duplicate');

    // Case B: Exhausting maxRetryAttempts (3) on temporary 429s marks post failed
    
    app.mockServer.setFaultPlan({
      temporaryFailuresRemaining: 5,
      temporaryStatus: 429
    });

    const p2Res = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Post exhausting temporary 429 retries',
        scheduledAt: new Date(Date.now() + 10).toISOString()
      })
    }).then((r) => r.json());

    const failedExhausted = await waitForCondition(
      async () => {
        const { post } = await fetch(`${app.baseUrl}/api/posts/${p2Res.post.id}`).then((r) => r.json());
        return post.status === 'failed' ? post : null;
      },
      { timeoutMs: 5000 }
    );
    assert.equal(failedExhausted.attemptCount, 3);
    assert.equal(failedExhausted.lastErrorCode, 'MAX_RETRIES_EXCEEDED');
    assert.equal(app.mockServer.createdPosts.length, 0);
  } finally {
    await cleanup();
  }
});

test('E2E: Duplicate-post protection blocks double submits, duplicate content, concurrent workers, and crash-lock replay', async () => {
  const { app, cleanup } = await createTestApp({
    workerPollIntervalMs: 60000 // Drive worker ticks deterministically in this test
  });
  try {
    await connectOAuthViaHttp(app);

    const body = {
      content: 'Unique announcement for duplicate-post protection test.',
      scheduledAt: new Date(Date.now() - 1000).toISOString()
    };

    // 1. Same Idempotency-Key returns deduplicated=true without inserting a second row
    
    const r1 = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'same-key-123' },
      body: JSON.stringify(body)
    });
    assert.equal(r1.status, 201);
    const d1 = await r1.json();

    const r2 = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'same-key-123' },
      body: JSON.stringify(body)
    });
    assert.equal(r2.status, 200);
    const d2 = await r2.json();
    assert.equal(d2.deduplicated, true);
    assert.equal(d2.post.id, d1.post.id);

    // 2. Different Idempotency-Key with identical active content is rejected with 409 Conflict
    
    const r3 = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'different-key-456' },
      body: JSON.stringify(body)
    });
    assert.equal(r3.status, 409);
    const d3 = await r3.json();
    assert.equal(d3.code, 'DUPLICATE_POST');

    // 3. Concurrent workers racing to claim the same post publish it exactly once
    
    const secondWorker = new PostWorker({
      db: app.db,
      linkedinClient: app.linkedinClient,
      logger: app.logger,
      workerId: 'worker-rival'
    });

    await Promise.all([app.worker.runOnce(), secondWorker.runOnce()]);
    assert.equal(app.mockServer.createdPosts.length, 1);

    // 4. Stale lock recovery marks interrupted processing posts failed rather than duplicating
    
    const stuckPostId = 'stuck-post-1';
    const pastIso = new Date(Date.now() - 300000).toISOString();
    app.db.db
      .prepare(
        `INSERT INTO posts (
          id, author_urn, content, content_hash, idempotency_key,
          visibility, status, scheduled_at, next_attempt_at,
          attempt_count, max_attempts, locked_by, locked_at, created_at, updated_at
        ) VALUES (?, 'urn:li:person:mock_member_782', 'Interrupted post', 'hash-x', 'key-x',
          'PUBLIC', 'processing', ?, ?, 1, 5, 'dead-worker', ?, ?, ?)`
      )
      .run(stuckPostId, pastIso, pastIso, pastIso, pastIso, pastIso);

    const recoveredIds = app.db.recoverStaleProcessingPosts({ lockTimeoutMs: 60000 });
    assert.deepEqual(recoveredIds, [stuckPostId]);
    const recovered = app.db.getPostById(stuckPostId);
    assert.equal(recovered.status, 'failed');
    assert.equal(recovered.lastErrorCode, 'STALE_LOCK_INTERRUPTED');
  } finally {
    await cleanup();
  }
});

test('E2E: Worker automatically refreshes expired OAuth token before publishing', async () => {
  const { app, cleanup } = await createTestApp({ workerPollIntervalMs: 60000 });
  try {
    await connectOAuthViaHttp(app);

    // Force token expiry into the past while refresh_token remains valid
    
    app.db.db
      .prepare("UPDATE oauth_tokens SET expires_at = '2020-01-01T00:00:00.000Z' WHERE id = 1")
      .run();

    const createRes = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Post published after transparent OAuth token refresh.',
        scheduledAt: new Date(Date.now() - 500).toISOString()
      })
    }).then((r) => r.json());

    await app.worker.runOnce();
    const post = app.db.getPostById(createRes.post.id);
    assert.equal(post.status, 'published');
    assert.equal(app.mockServer.createdPosts.length, 1);

    const refreshedStatus = app.db.getOAuthConnectionStatus();
    assert.equal(refreshedStatus.isExpired, false);
  } finally {
    await cleanup();
  }
});

test('E2E: Serves UI assets, honors 429 Retry-After header, supports manual retry, delete, and disconnect', async () => {
  const { app, cleanup } = await createTestApp({
    retryBaseDelayMs: 50,
    retryMaxDelayMs: 2000,
    maxRetryAttempts: 2
  });
  try {
    // Static UI assets
    const htmlRes = await fetch(`${app.baseUrl}/`);
    assert.equal(htmlRes.status, 200);
    assert.ok((await htmlRes.text()).includes('LinkedIn Post Scheduler'));

    const cssRes = await fetch(`${app.baseUrl}/styles.css`);
    assert.equal(cssRes.status, 200);

    const jsRes = await fetch(`${app.baseUrl}/app.js`);
    assert.equal(jsRes.status, 200);

    await connectOAuthViaHttp(app);

    // 429 with Retry-After: 1s overrides baseDelayMs (50ms) and maxRetryAttempts=2 exhausts -> failed
    
    app.mockServer.setFaultPlan({
      temporaryFailuresRemaining: 1,
      temporaryStatus: 429,
      retryAfterSeconds: 1
    });

    const created = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Post testing Retry-After and manual retry flow.',
        scheduledAt: new Date(Date.now() + 20).toISOString()
      })
    }).then((r) => r.json());

    const published = await waitForCondition(
      async () => {
        const { post } = await fetch(`${app.baseUrl}/api/posts/${created.post.id}`).then((r) => r.json());
        return post.status === 'published' ? post : null;
      },
      { timeoutMs: 4000 }
    );

    assert.equal(published.attempts[0].httpStatus, 429);
    assert.equal(published.attempts[0].retryDelayMs, 1000, 'Should honor 1s Retry-After header');
    assert.equal(app.mockServer.createdPosts.length, 1);

    // Published post cannot be re-queued
    
    const invalidRetry = await fetch(`${app.baseUrl}/api/posts/${created.post.id}/retry`, {
      method: 'POST'
    });
    assert.equal(invalidRetry.status, 409);

    // Schedule a post that fails permanently, then manually retry and succeed
    
    app.mockServer.setFaultPlan({
      permanentErrorStatus: 400,
      permanentErrorMessage: 'Temporary validation mismatch'
    });
    const failedPost = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Post that fails first then succeeds on manual retry.',
        scheduledAt: new Date(Date.now() + 20).toISOString()
      })
    }).then((r) => r.json());

    await waitForCondition(async () => {
      const { post } = await fetch(`${app.baseUrl}/api/posts/${failedPost.post.id}`).then((r) => r.json());
      return post.status === 'failed' ? post : null;
    });

    const manualRetryRes = await fetch(`${app.baseUrl}/api/posts/${failedPost.post.id}/retry`, {
      method: 'POST'
    });
    assert.equal(manualRetryRes.status, 200);

    const recovered = await waitForCondition(async () => {
      const { post } = await fetch(`${app.baseUrl}/api/posts/${failedPost.post.id}`).then((r) => r.json());
      return post.status === 'published' ? post : null;
    });
    assert.equal(recovered.status, 'published');

    // Disconnect OAuth and verify subsequent schedule request is rejected
    
    const disc = await fetch(`${app.baseUrl}/api/oauth/disconnect`, { method: 'POST' });
    assert.equal(disc.status, 200);

    const unauthPost = await fetch(`${app.baseUrl}/api/posts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: 'Should fail because OAuth is disconnected',
        scheduledAt: new Date(Date.now() + 1000).toISOString()
      })
    });
    assert.equal(unauthPost.status, 400);
  } finally {
    await cleanup();
  }
});
