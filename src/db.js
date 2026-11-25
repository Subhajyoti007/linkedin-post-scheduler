import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { PROJECT_ROOT } from './config.js';
import { hashPostContent } from './crypto.js';

const SCHEMA_PATH = path.join(PROJECT_ROOT, 'docs', 'schema.sql');

export class ConflictError extends Error {
  constructor(message, code = 'CONFLICT', details = null) {
    super(message);
    this.name = 'ConflictError';
    this.code = code;
    this.details = details;
  }
}

export class ValidationError extends Error {
  constructor(message, code = 'VALIDATION_ERROR') {
    super(message);
    this.name = 'ValidationError';
    this.code = code;
  }
}

function mapAttemptRow(row) {
  return {
    id: row.id,
    postId: row.post_id,
    attemptNumber: row.attempt_number,
    outcome: row.outcome,
    httpStatus: row.http_status,
    errorCode: row.error_code,
    errorMessage: row.error_message,
    retryDelayMs: row.retry_delay_ms,
    nextAttemptAt: row.next_attempt_at,
    durationMs: row.duration_ms,
    responseUrn: row.response_urn,
    createdAt: row.created_at
  };
}

function mapPostRow(row, attempts = []) {
  if (!row) return null;
  return {
    id: row.id,
    authorUrn: row.author_urn,
    content: row.content,
    contentHash: row.content_hash,
    idempotencyKey: row.idempotency_key,
    visibility: row.visibility,
    status: row.status,
    scheduledAt: row.scheduled_at,
    nextAttemptAt: row.next_attempt_at,
    attemptCount: row.attempt_count,
    maxAttempts: row.max_attempts,
    lockedBy: row.locked_by,
    lockedAt: row.locked_at,
    publishedPostUrn: row.published_post_urn,
    publishedAt: row.published_at,
    lastHttpStatus: row.last_http_status,
    lastErrorCode: row.last_error_code,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    attempts
  };
}

/**
 * SQLite persistence layer backed by Node's built-in node:sqlite DatabaseSync.
 */
export class AppDatabase {
  constructor({ databasePath, cipher }) {
    if (!cipher) throw new Error('TokenCipher instance is required.');
    this.databasePath = databasePath;
    this.cipher = cipher;

    if (databasePath !== ':memory:') {
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    }

    this.db = new DatabaseSync(databasePath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');

    const schemaSql = fs.readFileSync(SCHEMA_PATH, 'utf8');
    this.db.exec(schemaSql);
  }

  close() {
    this.db.close();
  }

  withTransaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {
        // Ignore rollback errors if transaction already closed
      }
      throw err;
    }
  }

  // -------------------- OAuth Configuration & States --------------------

  saveOAuthConfig({ clientId, clientSecret, redirectUri, scopes = 'openid profile w_member_social' }) {
    const cleanClientId = String(clientId || '').trim();
    const cleanRedirectUri = String(redirectUri || '').trim();
    const cleanScopes =
      String(scopes || 'openid profile w_member_social')
        .trim()
        .split(/[\s,]+/)
        .filter(Boolean)
        .join(' ') || 'openid profile w_member_social';
    if (!cleanClientId) throw new ValidationError('LinkedIn Client ID is required.');
    if (!cleanRedirectUri) throw new ValidationError('Redirect URI is required.');

    let parsedUrl;
    try {
      parsedUrl = new URL(cleanRedirectUri);
    } catch {
      throw new ValidationError('Redirect URI must be a valid URL.');
    }
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new ValidationError('Redirect URI must start with http:// or https://.');
    }

    const now = new Date().toISOString();

    return this.withTransaction(() => {
      const existing = this.db
        .prepare('SELECT client_secret_encrypted, created_at FROM oauth_configs WHERE id = 1')
        .get();

      let secretEncrypted;
      if (clientSecret && String(clientSecret).trim()) {
        secretEncrypted = this.cipher.encrypt(String(clientSecret).trim());
      } else if (existing?.client_secret_encrypted) {
        secretEncrypted = existing.client_secret_encrypted;
      } else {
        throw new ValidationError('LinkedIn Client Secret is required.');
      }

      this.db
        .prepare(
          `INSERT INTO oauth_configs (
            id, client_id, client_secret_encrypted, redirect_uri, scopes, created_at, updated_at
          ) VALUES (1, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            client_id = excluded.client_id,
            client_secret_encrypted = excluded.client_secret_encrypted,
            redirect_uri = excluded.redirect_uri,
            scopes = excluded.scopes,
            updated_at = excluded.updated_at`
        )
        .run(
          cleanClientId,
          secretEncrypted,
          cleanRedirectUri,
          cleanScopes,
          existing?.created_at || now,
          now
        );

      return this.getOAuthConfigStatus();
    });
  }

  getOAuthConfigStatus() {
    const row = this.db
      .prepare('SELECT client_id, client_secret_encrypted, redirect_uri, scopes, updated_at FROM oauth_configs WHERE id = 1')
      .get();
    if (!row) {
      return {
        configured: false,
        clientId: '',
        redirectUri: '',
        scopes: 'openid profile w_member_social',
        hasClientSecret: false,
        updatedAt: null
      };
    }
    return {
      configured: Boolean(row.client_id && row.client_secret_encrypted),
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      scopes: row.scopes,
      hasClientSecret: Boolean(row.client_secret_encrypted),
      updatedAt: row.updated_at
    };
  }

  getDecryptedOAuthConfig() {
    const row = this.db
      .prepare('SELECT client_id, client_secret_encrypted, redirect_uri, scopes FROM oauth_configs WHERE id = 1')
      .get();
    if (!row) return null;
    return {
      clientId: row.client_id,
      clientSecret: this.cipher.decrypt(row.client_secret_encrypted),
      redirectUri: row.redirect_uri,
      scopes: row.scopes
    };
  }

  createOAuthState(state, redirectUri, ttlMs = 10 * 60 * 1000) {
    const now = Date.now();
    const createdAt = new Date(now).toISOString();
    const expiresAt = new Date(now + ttlMs).toISOString();

    this.withTransaction(() => {
      this.db.prepare('DELETE FROM oauth_states WHERE expires_at <= ?').run(createdAt);
      this.db
        .prepare(
          'INSERT INTO oauth_states (state, redirect_uri, expires_at, created_at) VALUES (?, ?, ?, ?)'
        )
        .run(state, redirectUri, expiresAt, createdAt);
    });
  }

  consumeOAuthState(state) {
    if (!state) return null;
    const now = new Date().toISOString();
    return this.withTransaction(() => {
      const row = this.db
        .prepare('SELECT state, redirect_uri, expires_at FROM oauth_states WHERE state = ?')
        .get(state);
      if (!row) return null;
      this.db.prepare('DELETE FROM oauth_states WHERE state = ?').run(state);
      if (row.expires_at <= now) return null;
      return {
        state: row.state,
        redirectUri: row.redirect_uri,
        expiresAt: row.expires_at
      };
    });
  }

  // -------------------- OAuth Tokens --------------------

  saveOAuthTokens({
    authorUrn,
    memberSub,
    memberName = null,
    memberEmail = null,
    memberPicture = null,
    accessToken,
    refreshToken = null,
    tokenType = 'Bearer',
    scope = null,
    expiresAt,
    refreshExpiresAt = null
  }) {
    const now = new Date().toISOString();
    const accessEncrypted = this.cipher.encrypt(accessToken);
    const refreshEncrypted = refreshToken ? this.cipher.encrypt(refreshToken) : null;

    return this.withTransaction(() => {
      const existing = this.db
        .prepare('SELECT created_at, refresh_token_encrypted FROM oauth_tokens WHERE id = 1')
        .get();

      this.db
        .prepare(
          `INSERT INTO oauth_tokens (
            id, author_urn, member_sub, member_name, member_email, member_picture,
            access_token_encrypted, refresh_token_encrypted, token_type, scope,
            expires_at, refresh_expires_at, created_at, updated_at
          ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            author_urn = excluded.author_urn,
            member_sub = excluded.member_sub,
            member_name = excluded.member_name,
            member_email = excluded.member_email,
            member_picture = excluded.member_picture,
            access_token_encrypted = excluded.access_token_encrypted,
            refresh_token_encrypted = COALESCE(excluded.refresh_token_encrypted, oauth_tokens.refresh_token_encrypted),
            token_type = excluded.token_type,
            scope = excluded.scope,
            expires_at = excluded.expires_at,
            refresh_expires_at = COALESCE(excluded.refresh_expires_at, oauth_tokens.refresh_expires_at),
            updated_at = excluded.updated_at`
        )
        .run(
          authorUrn,
          memberSub,
          memberName,
          memberEmail,
          memberPicture,
          accessEncrypted,
          refreshEncrypted ?? existing?.refresh_token_encrypted ?? null,
          tokenType,
          scope,
          expiresAt,
          refreshExpiresAt,
          existing?.created_at || now,
          now
        );

      return this.getOAuthConnectionStatus();
    });
  }

  getOAuthConnectionStatus() {
    const row = this.db
      .prepare(
        `SELECT author_urn, member_sub, member_name, member_email, member_picture,
                token_type, scope, expires_at, refresh_expires_at,
                refresh_token_encrypted IS NOT NULL AS has_refresh_token,
                updated_at
         FROM oauth_tokens WHERE id = 1`
      )
      .get();

    if (!row) {
      return {
        connected: false,
        profile: null,
        expiresAt: null,
        isExpired: false,
        hasRefreshToken: false,
        scope: null,
        updatedAt: null
      };
    }

    const nowIso = new Date().toISOString();
    return {
      connected: true,
      profile: {
        authorUrn: row.author_urn,
        sub: row.member_sub,
        name: row.member_name,
        email: row.member_email,
        picture: row.member_picture
      },
      expiresAt: row.expires_at,
      isExpired: row.expires_at <= nowIso,
      hasRefreshToken: Boolean(row.has_refresh_token),
      scope: row.scope,
      updatedAt: row.updated_at
    };
  }

  getDecryptedOAuthTokens() {
    const row = this.db.prepare('SELECT * FROM oauth_tokens WHERE id = 1').get();
    if (!row) return null;
    return {
      authorUrn: row.author_urn,
      memberSub: row.member_sub,
      memberName: row.member_name,
      accessToken: this.cipher.decrypt(row.access_token_encrypted),
      refreshToken: row.refresh_token_encrypted
        ? this.cipher.decrypt(row.refresh_token_encrypted)
        : null,
      tokenType: row.token_type,
      scope: row.scope,
      expiresAt: row.expires_at,
      refreshExpiresAt: row.refresh_expires_at
    };
  }

  deleteOAuthTokens() {
    this.db.prepare('DELETE FROM oauth_tokens WHERE id = 1').run();
  }

  // -------------------- Posts & Duplicate Protection --------------------

  createPost({
    id,
    authorUrn,
    content,
    idempotencyKey,
    visibility = 'PUBLIC',
    scheduledAt,
    maxAttempts = 5
  }) {
    const cleanContent = String(content || '').trim();
    if (!cleanContent) {
      throw new ValidationError('Post content cannot be empty.');
    }
    if (cleanContent.length > 3000) {
      throw new ValidationError('Post content exceeds LinkedIn limit of 3,000 characters.');
    }
    if (visibility !== 'PUBLIC' && visibility !== 'CONNECTIONS') {
      throw new ValidationError('Visibility must be PUBLIC or CONNECTIONS.');
    }
    const parsedSchedule = Date.parse(scheduledAt);
    if (!Number.isFinite(parsedSchedule)) {
      throw new ValidationError('Scheduled date/time must be a valid ISO timestamp.');
    }

    const scheduledIso = new Date(parsedSchedule).toISOString();
    const contentHash = hashPostContent(cleanContent);
    const now = new Date().toISOString();

    return this.withTransaction(() => {
      // Layer 1: Idempotency key guard (prevents double-click / network retry duplicate inserts)
      const byKey = this.db
        .prepare('SELECT * FROM posts WHERE idempotency_key = ?')
        .get(idempotencyKey);
      if (byKey) {
        if (byKey.content_hash === contentHash && byKey.author_urn === authorUrn) {
          return {
            post: this.#hydratePost(byKey),
            deduplicated: true
          };
        }
        throw new ConflictError(
          'Idempotency key already used with different post content.',
          'IDEMPOTENCY_KEY_CONFLICT'
        );
      }

      // Layer 2: Active / already-published identical content guard per author
      const duplicate = this.db
        .prepare(
          `SELECT id, status, scheduled_at, published_post_urn
           FROM posts
           WHERE author_urn = ?
             AND content_hash = ?
             AND status IN ('scheduled', 'processing', 'published')
           ORDER BY created_at DESC
           LIMIT 1`
        )
        .get(authorUrn, contentHash);

      if (duplicate) {
        throw new ConflictError(
          `Duplicate post prevented: identical content already exists in status "${duplicate.status}" (post ${duplicate.id}).`,
          'DUPLICATE_POST',
          { existingPostId: duplicate.id, existingStatus: duplicate.status }
        );
      }

      this.db
        .prepare(
          `INSERT INTO posts (
            id, author_urn, content, content_hash, idempotency_key,
            visibility, status, scheduled_at, next_attempt_at,
            attempt_count, max_attempts, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, 0, ?, ?, ?)`
        )
        .run(
          id,
          authorUrn,
          cleanContent,
          contentHash,
          idempotencyKey,
          visibility,
          scheduledIso,
          scheduledIso,
          maxAttempts,
          now,
          now
        );

      const created = this.db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
      return {
        post: this.#hydratePost(created),
        deduplicated: false
      };
    });
  }

  #hydratePost(row) {
    if (!row) return null;
    const attempts = this.db
      .prepare('SELECT * FROM post_attempts WHERE post_id = ? ORDER BY id ASC')
      .all(row.id)
      .map(mapAttemptRow);
    return mapPostRow(row, attempts);
  }

  getPostById(id) {
    const row = this.db.prepare('SELECT * FROM posts WHERE id = ?').get(id);
    return this.#hydratePost(row);
  }

  listPosts({ limit = 50 } = {}) {
    const rows = this.db
      .prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT ?')
      .all(limit);
    return rows.map((row) => this.#hydratePost(row));
  }

  retryFailedPost(postId, nowIso = new Date().toISOString()) {
    return this.withTransaction(() => {
      const row = this.db.prepare('SELECT * FROM posts WHERE id = ?').get(postId);
      if (!row) return null;
      if (row.published_post_urn) {
        throw new ConflictError(
          'Post already has a published LinkedIn URN and cannot be re-published.',
          'ALREADY_PUBLISHED'
        );
      }
      if (row.status !== 'failed') {
        throw new ConflictError(
          `Only failed posts can be manually retried (current status: ${row.status}).`,
          'INVALID_STATUS'
        );
      }

      this.db
        .prepare(
          `UPDATE posts
           SET status = 'scheduled',
               attempt_count = 0,
               next_attempt_at = ?,
               locked_by = NULL,
               locked_at = NULL,
               last_http_status = NULL,
               last_error_code = NULL,
               last_error = NULL,
               updated_at = ?
           WHERE id = ? AND status = 'failed' AND published_post_urn IS NULL`
        )
        .run(nowIso, nowIso, postId);

      return this.getPostById(postId);
    });
  }

  deletePost(postId) {
    return this.withTransaction(() => {
      const row = this.db.prepare('SELECT status FROM posts WHERE id = ?').get(postId);
      if (!row) return { deleted: false, reason: 'not_found' };
      if (row.status === 'processing') {
        throw new ConflictError(
          'Cannot delete a post while it is currently processing.',
          'POST_PROCESSING'
        );
      }
      const res = this.db
        .prepare("DELETE FROM posts WHERE id = ? AND status != 'processing'")
        .run(postId);
      return { deleted: res.changes === 1 };
    });
  }

  // -------------------- Worker Atomic Claim & Transitions --------------------

  /**
   * Atomically claims the next due post for processing.
   * Ensures at most one worker ever processes a scheduled post, and never touches
   * any post that already has a published_post_urn.
   */
  claimNextDuePost({ workerId, nowIso = new Date().toISOString() }) {
    return this.withTransaction(() => {
      const candidate = this.db
        .prepare(
          `SELECT id
           FROM posts
           WHERE status = 'scheduled'
             AND next_attempt_at <= ?
             AND published_post_urn IS NULL
           ORDER BY next_attempt_at ASC, created_at ASC
           LIMIT 1`
        )
        .get(nowIso);

      if (!candidate) return null;

      const updated = this.db
        .prepare(
          `UPDATE posts
           SET status = 'processing',
               locked_by = ?,
               locked_at = ?,
               attempt_count = attempt_count + 1,
               updated_at = ?
           WHERE id = ?
             AND status = 'scheduled'
             AND next_attempt_at <= ?
             AND published_post_urn IS NULL`
        )
        .run(workerId, nowIso, nowIso, candidate.id, nowIso);

      if (updated.changes !== 1) return null;

      const claimed = this.db.prepare('SELECT * FROM posts WHERE id = ?').get(candidate.id);
      return mapPostRow(claimed, []);
    });
  }

  markPostPublished({
    postId,
    workerId,
    publishedPostUrn,
    attemptNumber,
    httpStatus = 201,
    durationMs = 0,
    nowIso = new Date().toISOString()
  }) {
    if (!publishedPostUrn) {
      throw new Error('publishedPostUrn is required when marking a post published.');
    }

    return this.withTransaction(() => {
      const res = this.db
        .prepare(
          `UPDATE posts
           SET status = 'published',
               published_post_urn = ?,
               published_at = ?,
               locked_by = NULL,
               locked_at = NULL,
               last_http_status = ?,
               last_error_code = NULL,
               last_error = NULL,
               updated_at = ?
           WHERE id = ?
             AND status = 'processing'
             AND locked_by = ?
             AND published_post_urn IS NULL`
        )
        .run(publishedPostUrn, nowIso, httpStatus, nowIso, postId, workerId);

      if (res.changes !== 1) {
        throw new ConflictError(
          `Failed to mark post ${postId} published; lock lost or already published.`,
          'PUBLISH_STATE_CONFLICT'
        );
      }

      this.db
        .prepare(
          `INSERT INTO post_attempts (
            post_id, attempt_number, outcome, http_status, duration_ms, response_urn, created_at
          ) VALUES (?, ?, 'succeeded', ?, ?, ?, ?)`
        )
        .run(postId, attemptNumber, httpStatus, durationMs, publishedPostUrn, nowIso);

      return this.getPostById(postId);
    });
  }

  schedulePostRetry({
    postId,
    workerId,
    attemptNumber,
    httpStatus = null,
    errorCode,
    errorMessage,
    retryDelayMs,
    nextAttemptAt,
    durationMs = 0,
    nowIso = new Date().toISOString()
  }) {
    return this.withTransaction(() => {
      const res = this.db
        .prepare(
          `UPDATE posts
           SET status = 'scheduled',
               next_attempt_at = ?,
               locked_by = NULL,
               locked_at = NULL,
               last_http_status = ?,
               last_error_code = ?,
               last_error = ?,
               updated_at = ?
           WHERE id = ?
             AND status = 'processing'
             AND locked_by = ?
             AND published_post_urn IS NULL`
        )
        .run(
          nextAttemptAt,
          httpStatus,
          errorCode,
          errorMessage,
          nowIso,
          postId,
          workerId
        );

      if (res.changes !== 1) {
        throw new ConflictError(
          `Failed to schedule retry for post ${postId}; state changed unexpectedly.`,
          'RETRY_STATE_CONFLICT'
        );
      }

      this.db
        .prepare(
          `INSERT INTO post_attempts (
            post_id, attempt_number, outcome, http_status, error_code,
            error_message, retry_delay_ms, next_attempt_at, duration_ms, created_at
          ) VALUES (?, ?, 'temporary_error', ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
          postId,
          attemptNumber,
          httpStatus,
          errorCode,
          errorMessage,
          retryDelayMs,
          nextAttemptAt,
          durationMs,
          nowIso
        );

      return this.getPostById(postId);
    });
  }

  markPostFailed({
    postId,
    workerId,
    attemptNumber,
    outcome = 'permanent_error',
    httpStatus = null,
    errorCode,
    errorMessage,
    durationMs = 0,
    nowIso = new Date().toISOString()
  }) {
    return this.withTransaction(() => {
      const res = this.db
        .prepare(
          `UPDATE posts
           SET status = 'failed',
               locked_by = NULL,
               locked_at = NULL,
               last_http_status = ?,
               last_error_code = ?,
               last_error = ?,
               updated_at = ?
           WHERE id = ?
             AND status = 'processing'
             AND (locked_by = ? OR locked_by IS NULL)
             AND published_post_urn IS NULL`
        )
        .run(httpStatus, errorCode, errorMessage, nowIso, postId, workerId);

      if (res.changes !== 1) {
        throw new ConflictError(
          `Failed to mark post ${postId} failed; state changed unexpectedly.`,
          'FAIL_STATE_CONFLICT'
        );
      }

      this.db
        .prepare(
          `INSERT INTO post_attempts (
            post_id, attempt_number, outcome, http_status, error_code,
            error_message, duration_ms, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(postId, attemptNumber, outcome, httpStatus, errorCode, errorMessage, durationMs, nowIso);

      return this.getPostById(postId);
    });
  }

  /**
   * Recovers posts left stuck in "processing" after an unexpected process crash.
   * Marks them "failed" rather than automatically re-sending so an interrupted
   * HTTP call cannot cause duplicate LinkedIn posts.
   */
  recoverStaleProcessingPosts({ lockTimeoutMs, nowMs = Date.now() }) {
    const cutoffIso = new Date(nowMs - lockTimeoutMs).toISOString();
    const nowIso = new Date(nowMs).toISOString();

    return this.withTransaction(() => {
      const stale = this.db
        .prepare(
          `SELECT id, attempt_count
           FROM posts
           WHERE status = 'processing'
             AND locked_at IS NOT NULL
             AND locked_at <= ?
             AND published_post_urn IS NULL`
        )
        .all(cutoffIso);

      const message =
        'Worker interrupted while publishing (stale lock recovered). Marked failed to prevent duplicate posts.';

      for (const row of stale) {
        this.db
          .prepare(
            `UPDATE posts
             SET status = 'failed',
                 locked_by = NULL,
                 locked_at = NULL,
                 last_error_code = 'STALE_LOCK_INTERRUPTED',
                 last_error = ?,
                 updated_at = ?
             WHERE id = ? AND status = 'processing' AND published_post_urn IS NULL`
          )
          .run(message, nowIso, row.id);

        this.db
          .prepare(
            `INSERT INTO post_attempts (
              post_id, attempt_number, outcome, error_code, error_message, created_at
            ) VALUES (?, ?, 'skipped_duplicate', 'STALE_LOCK_INTERRUPTED', ?, ?)`
          )
          .run(row.id, Math.max(1, row.attempt_count), message, nowIso);
      }

      return stale.map((r) => r.id);
    });
  }

  // -------------------- Application Logs --------------------

  insertLog({ level, component, event, postId = null, message, metaJson = null, createdAt }) {
    this.db
      .prepare(
        `INSERT INTO app_logs (level, component, event, post_id, message, meta_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(level, component, event, postId, message, metaJson, createdAt);
  }

  listLogs({ level = null, limit = 100 } = {}) {
    const rows = level
      ? this.db
          .prepare('SELECT * FROM app_logs WHERE level = ? ORDER BY id DESC LIMIT ?')
          .all(level, limit)
      : this.db.prepare('SELECT * FROM app_logs ORDER BY id DESC LIMIT ?').all(limit);

    return rows.map((r) => ({
      id: r.id,
      level: r.level,
      component: r.component,
      event: r.event,
      postId: r.post_id,
      message: r.message,
      meta: r.meta_json ? JSON.parse(r.meta_json) : null,
      createdAt: r.created_at
    }));
  }
}
