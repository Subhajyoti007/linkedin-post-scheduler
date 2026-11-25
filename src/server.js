import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { PROJECT_ROOT } from './config.js';
import { generateRandomToken } from './crypto.js';
import { ConflictError, ValidationError } from './db.js';
import { LinkedInApiError } from './linkedin.js';

const PUBLIC_DIR = path.join(PROJECT_ROOT, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png'
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  res.end(body);
}

function sendRedirect(res, location) {
  res.writeHead(302, {
    Location: location,
    'Cache-Control': 'no-store'
  });
  res.end();
}

async function readJsonBody(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      throw new ValidationError('Request body too large.');
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new ValidationError('Request body must be valid JSON.');
  }
}

/**
 * HTTP Server exposing OAuth 2.0 routes, scheduling REST API, logs, and static UI.
 */
export class AppServer {
  constructor({
    host = '127.0.0.1',
    port = 3000,
    config,
    db,
    linkedinClient,
    worker,
    logger,
    mockServer = null
  }) {
    this.host = host;
    this.port = port;
    this.config = config;
    this.db = db;
    this.linkedinClient = linkedinClient;
    this.worker = worker;
    this.logger = logger;
    this.mockServer = mockServer;
    this.server = null;
    this.baseUrl = null;
  }

  async start() {
    if (this.server) return this.baseUrl;
    this.server = http.createServer((req, res) => {
      this.#handleRequest(req, res).catch((err) => {
        this.#handleError(res, err);
      });
    });

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, resolve);
    });

    const addr = this.server.address();
    this.baseUrl = `http://${this.host}:${addr.port}`;
    this.logger.info('server', 'HTTP_SERVER_STARTED', `Listening on ${this.baseUrl}`, {
      baseUrl: this.baseUrl,
      mode: this.config.linkedinMode
    });
    return this.baseUrl;
  }

  async stop() {
    if (!this.server) return;
    await new Promise((resolve) => this.server.close(resolve));
    this.server = null;
    this.baseUrl = null;
    this.logger.info('server', 'HTTP_SERVER_STOPPED', 'HTTP server closed.');
  }

  async #handleRequest(req, res) {
    const url = new URL(req.url, this.baseUrl || `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const method = req.method || 'GET';

    // Health check
    if (method === 'GET' && pathname === '/api/health') {
      return sendJson(res, 200, {
        ok: true,
        mode: this.config.linkedinMode,
        worker: this.worker.getStatus(),
        db: 'ok',
        time: new Date().toISOString()
      });
    }

    // OAuth configuration & connection status (secrets never exposed)
    if (method === 'GET' && pathname === '/api/oauth/status') {
      const cfg = this.db.getOAuthConfigStatus();
      if (!cfg.redirectUri) {
        cfg.redirectUri = `${this.baseUrl || `http://localhost:${this.port}`}/auth/linkedin/callback`;
      }
      return sendJson(res, 200, {
        mode: this.config.linkedinMode,
        config: cfg,
        connection: this.db.getOAuthConnectionStatus()
      });
    }

    if (method === 'POST' && pathname === '/api/oauth/credentials') {
      const body = await readJsonBody(req);
      const saved = this.db.saveOAuthConfig({
        clientId: body.clientId,
        clientSecret: body.clientSecret,
        redirectUri:
          body.redirectUri ||
          `${this.baseUrl || `http://localhost:${this.port}`}/auth/linkedin/callback`,
        scopes: body.scopes
      });
      this.logger.info('oauth', 'OAUTH_CREDENTIALS_SAVED', 'Saved encrypted LinkedIn OAuth credentials.', {
        clientId: saved.clientId,
        redirectUri: saved.redirectUri,
        scopes: saved.scopes
      });
      return sendJson(res, 200, { config: saved });
    }

    if (method === 'POST' && pathname === '/api/oauth/disconnect') {
      this.db.deleteOAuthTokens();
      this.logger.info('oauth', 'OAUTH_DISCONNECTED', 'Disconnected LinkedIn account and purged tokens.');
      return sendJson(res, 200, { ok: true, connection: this.db.getOAuthConnectionStatus() });
    }

    // Step 1 of 3-legged OAuth 2.0
    if (method === 'GET' && pathname === '/auth/linkedin') {
      const oauthConfig = this.db.getDecryptedOAuthConfig();
      if (!oauthConfig) {
        return sendRedirect(
          res,
          '/?oauth=error&message=' +
            encodeURIComponent('Please save your LinkedIn Client ID and Client Secret first.')
        );
      }

      const state = generateRandomToken(24);
      this.db.createOAuthState(state, oauthConfig.redirectUri);

      const authUrl = this.linkedinClient.buildAuthorizationUrl({
        clientId: oauthConfig.clientId,
        redirectUri: oauthConfig.redirectUri,
        state,
        scopes: oauthConfig.scopes
      });

      this.logger.info('oauth', 'OAUTH_AUTHORIZE_REDIRECT', 'Redirecting user to LinkedIn OAuth consent.', {
        redirectUri: oauthConfig.redirectUri,
        scopes: oauthConfig.scopes
      });
      return sendRedirect(res, authUrl);
    }

    // Step 2 of 3-legged OAuth 2.0
    if (method === 'GET' && pathname === '/auth/linkedin/callback') {
      const oauthError = url.searchParams.get('error');
      const oauthErrorDesc = url.searchParams.get('error_description');
      const state = url.searchParams.get('state');
      const code = url.searchParams.get('code');

      if (oauthError) {
        const baseMsg = oauthErrorDesc || oauthError;
        const msg =
          oauthError === 'invalid_scope_error'
            ? `${baseMsg}. Ensure "Sign In with LinkedIn using OpenID Connect" and "Share on LinkedIn" are added under Products in the LinkedIn Developer Portal (or match your app's Auth -> OAuth 2.0 scopes).`
            : baseMsg;
        this.logger.warn('oauth', 'OAUTH_CALLBACK_DENIED', `LinkedIn OAuth denied: ${baseMsg}`, {
          error: oauthError
        });
        return sendRedirect(res, `/?oauth=error&message=${encodeURIComponent(msg)}`);
      }

      const validState = this.db.consumeOAuthState(state);
      if (!validState) {
        this.logger.warn('oauth', 'OAUTH_STATE_INVALID', 'Rejected OAuth callback with invalid or expired state.');
        return sendRedirect(
          res,
          '/?oauth=error&message=' +
            encodeURIComponent('Invalid or expired OAuth state parameter. Please try connecting again.')
        );
      }

      if (!code) {
        return sendRedirect(
          res,
          '/?oauth=error&message=' + encodeURIComponent('Missing authorization code from LinkedIn.')
        );
      }

      const oauthConfig = this.db.getDecryptedOAuthConfig();
      if (!oauthConfig) {
        return sendRedirect(
          res,
          '/?oauth=error&message=' + encodeURIComponent('OAuth configuration missing on server.')
        );
      }

      try {
        const tokenSet = await this.linkedinClient.exchangeCodeForTokens({
          code,
          clientId: oauthConfig.clientId,
          clientSecret: oauthConfig.clientSecret,
          redirectUri: validState.redirectUri
        });

        const profile = await this.linkedinClient.getUserInfo(
          tokenSet.accessToken,
          tokenSet.idToken
        );
        this.db.saveOAuthTokens({
          authorUrn: profile.authorUrn,
          memberSub: profile.sub,
          memberName: profile.name,
          memberEmail: profile.email,
          memberPicture: profile.picture,
          accessToken: tokenSet.accessToken,
          refreshToken: tokenSet.refreshToken,
          tokenType: tokenSet.tokenType,
          scope: tokenSet.scope || oauthConfig.scopes,
          expiresAt: tokenSet.expiresAt,
          refreshExpiresAt: tokenSet.refreshExpiresAt
        });

        this.logger.info('oauth', 'OAUTH_CONNECTED', `Connected LinkedIn account (${profile.authorUrn}).`, {
          authorUrn: profile.authorUrn,
          expiresAt: tokenSet.expiresAt
        });

        return sendRedirect(res, '/?oauth=connected');
      } catch (err) {
        this.logger.error('oauth', 'OAUTH_EXCHANGE_FAILED', `OAuth callback failed: ${err.message}`, {
          error: err
        });
        return sendRedirect(
          res,
          '/?oauth=error&message=' + encodeURIComponent(err.message || 'OAuth exchange failed')
        );
      }
    }

    // Scheduled Posts REST API
    if (method === 'GET' && pathname === '/api/posts') {
      const limit = Math.min(100, Math.max(1, Number(url.searchParams.get('limit') || 50)));
      return sendJson(res, 200, { posts: this.db.listPosts({ limit }) });
    }

    if (method === 'POST' && pathname === '/api/posts') {
      const body = await readJsonBody(req);
      const connection = this.db.getOAuthConnectionStatus();
      if (!connection.connected) {
        throw new ValidationError(
          'Connect your LinkedIn OAuth account before scheduling a post.',
          'OAUTH_NOT_CONNECTED'
        );
      }
      if (connection.isExpired && !connection.hasRefreshToken) {
        throw new ValidationError(
          'Your LinkedIn OAuth token has expired. Please reconnect your account.',
          'OAUTH_TOKEN_EXPIRED'
        );
      }

      const id = crypto.randomUUID();
      const idempotencyKey =
        String(req.headers['idempotency-key'] || body.idempotencyKey || '').trim() ||
        crypto.randomUUID();

      const result = this.db.createPost({
        id,
        authorUrn: connection.profile.authorUrn,
        content: body.content,
        idempotencyKey,
        visibility: body.visibility || 'PUBLIC',
        scheduledAt: body.scheduledAt,
        maxAttempts: this.config.maxRetryAttempts
      });

      if (result.deduplicated) {
        this.logger.info(
          'server',
          'POST_IDEMPOTENT_REPLAY',
          'Returned existing scheduled post for matching idempotency key.',
          { idempotencyKey },
          result.post.id
        );
        return sendJson(res, 200, result);
      }

      this.logger.info(
        'server',
        'POST_SCHEDULED',
        `Scheduled post for ${result.post.scheduledAt}.`,
        {
          scheduledAt: result.post.scheduledAt,
          visibility: result.post.visibility,
          authorUrn: result.post.authorUrn
        },
        result.post.id
      );

      return sendJson(res, 201, result);
    }

    const postMatch = pathname.match(/^\/api\/posts\/([^/]+?)(?:\/(retry))?$/);
    if (postMatch) {
      const postId = decodeURIComponent(postMatch[1]);
      const action = postMatch[2];

      if (method === 'GET' && !action) {
        const post = this.db.getPostById(postId);
        if (!post) return sendJson(res, 404, { error: 'Post not found.' });
        return sendJson(res, 200, { post });
      }

      if (method === 'POST' && action === 'retry') {
        const post = this.db.retryFailedPost(postId);
        if (!post) return sendJson(res, 404, { error: 'Post not found.' });
        this.logger.info('server', 'POST_MANUAL_RETRY', 'Failed post manually re-queued.', null, postId);
        return sendJson(res, 200, { post });
      }

      if (method === 'DELETE' && !action) {
        const resDelete = this.db.deletePost(postId);
        if (!resDelete.deleted) return sendJson(res, 404, { error: 'Post not found.' });
        this.logger.info('server', 'POST_DELETED', 'Post deleted by user.', null, postId);
        return sendJson(res, 200, { deleted: true });
      }
    }

    // Structured Logs
    if (method === 'GET' && pathname === '/api/logs') {
      const level = url.searchParams.get('level') || null;
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get('limit') || 80)));
      return sendJson(res, 200, { logs: this.db.listLogs({ level, limit }) });
    }

    // Optional Mock Sandbox Inspection/Fault Controls (only when LINKEDIN_MODE=mock)
    if (this.mockServer && pathname === '/api/mock/state' && method === 'GET') {
      return sendJson(res, 200, this.mockServer.getState());
    }

    if (this.mockServer && pathname === '/api/mock/faults' && method === 'POST') {
      const body = await readJsonBody(req);
      if (body.reset) {
        this.mockServer.reset();
      } else {
        this.mockServer.setFaultPlan(body);
      }
      this.logger.info('server', 'MOCK_FAULT_PLAN_UPDATED', 'Updated mock LinkedIn server fault simulation.', body);
      return sendJson(res, 200, this.mockServer.getState());
    }

    // Static assets (index.html, styles.css, app.js)
    if (method === 'GET') {
      return this.#serveStatic(pathname, res);
    }

    return sendJson(res, 404, { error: 'Route not found.' });
  }

  #serveStatic(pathname, res) {
    const relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const resolved = path.resolve(PUBLIC_DIR, relativePath);
    if (!resolved.startsWith(PUBLIC_DIR + path.sep) && resolved !== PUBLIC_DIR) {
      return sendJson(res, 403, { error: 'Forbidden' });
    }
    if (!fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
      return sendJson(res, 404, { error: 'Not found' });
    }
    const ext = path.extname(resolved).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    const content = fs.readFileSync(resolved);
    res.writeHead(200, {
      'Content-Type': mime,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    res.end(content);
  }

  #handleError(res, err) {
    if (err instanceof ValidationError) {
      return sendJson(res, 400, { error: err.message, code: err.code });
    }
    if (err instanceof ConflictError) {
      return sendJson(res, 409, { error: err.message, code: err.code, details: err.details });
    }
    if (err instanceof LinkedInApiError) {
      return sendJson(res, err.httpStatus || 502, { error: err.message, code: err.errorCode });
    }
    this.logger.error('server', 'UNHANDLED_HTTP_ERROR', err.message, { error: err });
    return sendJson(res, 500, { error: 'Internal server error' });
  }
}
