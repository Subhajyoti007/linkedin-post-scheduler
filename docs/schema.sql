-- LinkedIn Post Scheduler Database Schema (SQLite)
-- Applied automatically on startup by src/db.js

-- 1. User-supplied LinkedIn OAuth application configuration
CREATE TABLE IF NOT EXISTS oauth_configs (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  client_id TEXT NOT NULL,
  client_secret_encrypted TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scopes TEXT NOT NULL DEFAULT 'openid profile w_member_social',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- 2. Short-lived CSRF state tokens for OAuth 2.0 authorization redirects
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  redirect_uri TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 3. Connected LinkedIn member identity and AES-256-GCM encrypted OAuth tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  author_urn TEXT NOT NULL,
  member_sub TEXT NOT NULL,
  member_name TEXT,
  member_email TEXT,
  member_picture TEXT,
  access_token_encrypted TEXT NOT NULL,
  refresh_token_encrypted TEXT,
  token_type TEXT NOT NULL DEFAULT 'Bearer',
  scope TEXT,
  expires_at TEXT NOT NULL,
  refresh_expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- 4. Scheduled posts and worker state machine
-- Exact allowed statuses: scheduled, processing, published, failed
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  author_urn TEXT NOT NULL,
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  visibility TEXT NOT NULL DEFAULT 'PUBLIC' CHECK (visibility IN ('PUBLIC', 'CONNECTIONS')),
  status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'processing', 'published', 'failed')),
  scheduled_at TEXT NOT NULL,
  next_attempt_at TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  locked_by TEXT,
  locked_at TEXT,
  published_post_urn TEXT UNIQUE,
  published_at TEXT,
  last_http_status INTEGER,
  last_error_code TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_due
  ON posts(status, next_attempt_at)
  WHERE status = 'scheduled';

CREATE INDEX IF NOT EXISTS idx_posts_dedupe
  ON posts(author_urn, content_hash, status);

-- 5. Immutable audit log of every publish attempt, retry delay, and error
CREATE TABLE IF NOT EXISTS post_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'temporary_error', 'permanent_error', 'skipped_duplicate')),
  http_status INTEGER,
  error_code TEXT,
  error_message TEXT,
  retry_delay_ms INTEGER,
  next_attempt_at TEXT,
  duration_ms INTEGER,
  response_urn TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_post_attempts_post
  ON post_attempts(post_id, attempt_number);

-- 6. Structured application and background worker logs (secrets redacted)
CREATE TABLE IF NOT EXISTS app_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level TEXT NOT NULL CHECK (level IN ('debug', 'info', 'warn', 'error')),
  component TEXT NOT NULL,
  event TEXT NOT NULL,
  post_id TEXT,
  message TEXT NOT NULL,
  meta_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_app_logs_created
  ON app_logs(created_at DESC);
