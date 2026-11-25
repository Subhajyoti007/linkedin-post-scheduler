import http from 'node:http';
import crypto from 'node:crypto';

function escapeHtml(str) {
  return String(str || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Local Mock LinkedIn OAuth 2.0 + /v2/userinfo + /rest/posts HTTP server.
 * Only started when LINKEDIN_MODE=mock or in automated tests.
 */
export class MockLinkedInServer {
  constructor({ host = '127.0.0.1', port = 0 } = {}) {
    this.host = host;
    this.port = port;
    this.server = null;
    this.baseUrl = null;

    this.issuedCodes = new Map();
    this.validTokens = new Map();
    this.createdPosts = [];
    this.postRequests = [];
    this.faultPlan = {
      temporaryFailuresRemaining: 0,
      temporaryStatus: 503,
      retryAfterSeconds: null,
      permanentErrorStatus: null,
      permanentErrorMessage: null
    };
  }

  reset() {
    this.issuedCodes.clear();
    this.validTokens.clear();
    this.createdPosts = [];
    this.postRequests = [];
    this.faultPlan = {
      temporaryFailuresRemaining: 0,
      temporaryStatus: 503,
      retryAfterSeconds: null,
      permanentErrorStatus: null,
      permanentErrorMessage: null
    };
  }

  setFaultPlan(plan = {}) {
    this.faultPlan = {
      temporaryFailuresRemaining: Number(plan.temporaryFailuresRemaining ?? 0),
      temporaryStatus: Number(plan.temporaryStatus ?? 503),
      retryAfterSeconds:
        plan.retryAfterSeconds === null || plan.retryAfterSeconds === undefined || plan.retryAfterSeconds === ''
          ? null
          : Number(plan.retryAfterSeconds),
      permanentErrorStatus:
        plan.permanentErrorStatus === null || plan.permanentErrorStatus === undefined || plan.permanentErrorStatus === ''
          ? null
          : Number(plan.permanentErrorStatus),
      permanentErrorMessage: plan.permanentErrorMessage || null
    };
  }

  getState() {
    return {
      baseUrl: this.baseUrl,
      faultPlan: { ...this.faultPlan },
      createdPosts: [...this.createdPosts],
      postRequests: [...this.postRequests]
    };
  }

  async start() {
    if (this.server) return this.baseUrl;
    this.server = http.createServer((req, res) => {
      this.#handleRequest(req, res).catch((err) => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: err.message }));
      });
    });

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.host, resolve);
    });

    const addr = this.server.address();
    this.baseUrl = `http://${this.host}:${addr.port}`;
    return this.baseUrl;
  }

  async stop() {
    if (!this.server) return;
    await new Promise((resolve) => this.server.close(resolve));
    this.server = null;
    this.baseUrl = null;
  }

  async #readBody(req) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
  }

  async #handleRequest(req, res) {
    const url = new URL(req.url, this.baseUrl || 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname === '/oauth/v2/authorization') {
      const clientId = url.searchParams.get('client_id') || '';
      const redirectUri = url.searchParams.get('redirect_uri') || '';
      const state = url.searchParams.get('state') || '';
      const scope = url.searchParams.get('scope') || '';
      const autoApprove = url.searchParams.get('auto_approve') === '1';

      if (!clientId || !redirectUri) {
        res.writeHead(400, { 'Content-Type': 'text/plain' });
        res.end('Missing client_id or redirect_uri');
        return;
      }

      const code = `mock_auth_code_${crypto.randomBytes(10).toString('hex')}`;
      this.issuedCodes.set(code, {
        clientId,
        redirectUri,
        scope,
        createdAt: Date.now()
      });

      const approveTarget = new URL(redirectUri);
      approveTarget.searchParams.set('code', code);
      approveTarget.searchParams.set('state', state);

      if (autoApprove) {
        res.writeHead(302, { Location: approveTarget.toString() });
        res.end();
        return;
      }

      const denyTarget = new URL(redirectUri);
      denyTarget.searchParams.set('error', 'user_cancelled_authorize');
      denyTarget.searchParams.set('error_description', 'User denied access in Sandbox Consent');
      denyTarget.searchParams.set('state', state);

      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Mock LinkedIn OAuth Consent</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f3f2ef; color: #1d2226; display: grid; place-items: center; min-height: 100vh; margin: 0; }
    .card { background: #fff; border-radius: 12px; padding: 28px; max-width: 440px; box-shadow: 0 8px 30px rgba(0,0,0,0.08); border: 1px solid #e0dfdc; }
    .badge { display: inline-block; background: #e8f3ff; color: #0a66c2; font-weight: 600; font-size: 12px; padding: 4px 10px; border-radius: 999px; margin-bottom: 12px; }
    h1 { font-size: 20px; margin: 0 0 8px; }
    p { color: #56687a; font-size: 14px; line-height: 1.5; }
    .scopes { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; margin: 16px 0; font-size: 13px; }
    .actions { display: flex; gap: 12px; margin-top: 20px; }
    a.btn { flex: 1; text-align: center; text-decoration: none; padding: 11px 16px; border-radius: 999px; font-weight: 600; font-size: 14px; }
    .approve { background: #0a66c2; color: #fff; }
    .deny { background: #fff; color: #56687a; border: 1px solid #cbd5e1; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">LinkedIn OAuth 2.0 Sandbox</div>
    <h1>Authorize Application</h1>
    <p>Client <code>${escapeHtml(clientId)}</code> is requesting access to your LinkedIn Sandbox profile.</p>
    <div class="scopes">
      <strong>Requested scopes:</strong><br/>
      <code>${escapeHtml(scope)}</code>
    </div>
    <p>Member: <strong>Alex Morgan (Sandbox)</strong> (<code>urn:li:person:mock_member_782</code>)</p>
    <div class="actions">
      <a class="btn deny" href="${escapeHtml(denyTarget.toString())}">Cancel</a>
      <a class="btn approve" href="${escapeHtml(approveTarget.toString())}">Allow Access</a>
    </div>
  </div>
</body>
</html>`);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/oauth/v2/accessToken') {
      const rawBody = await this.#readBody(req);
      const params = new URLSearchParams(rawBody);
      const grantType = params.get('grant_type');
      const clientId = params.get('client_id');
      const clientSecret = params.get('client_secret');

      if (!clientId || !clientSecret) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_client', error_description: 'Missing client credentials' }));
        return;
      }

      if (grantType === 'authorization_code') {
        const code = params.get('code');
        const redirectUri = params.get('redirect_uri');
        const record = this.issuedCodes.get(code);
        if (!record || record.clientId !== clientId || record.redirectUri !== redirectUri) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }));
          return;
        }
        this.issuedCodes.delete(code);

        const accessToken = `mock_access_${crypto.randomBytes(16).toString('hex')}`;
        const refreshToken = `mock_refresh_${crypto.randomBytes(16).toString('hex')}`;
        this.validTokens.set(accessToken, {
          sub: 'mock_member_782',
          name: 'Alex Morgan (Sandbox)',
          email: 'alex.morgan@example.com',
          scope: record.scope,
          refreshToken
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            access_token: accessToken,
            expires_in: 5184000,
            refresh_token: refreshToken,
            refresh_token_expires_in: 31536000,
            scope: record.scope,
            token_type: 'Bearer'
          })
        );
        return;
      }

      if (grantType === 'refresh_token') {
        const refreshToken = params.get('refresh_token');
        const existingEntry = [...this.validTokens.values()].find(
          (entry) => entry.refreshToken === refreshToken
        );
        if (!existingEntry) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant', error_description: 'Invalid refresh token' }));
          return;
        }
        const accessToken = `mock_access_${crypto.randomBytes(16).toString('hex')}`;
        this.validTokens.set(accessToken, {
          ...existingEntry,
          refreshToken
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            access_token: accessToken,
            expires_in: 5184000,
            refresh_token: refreshToken,
            scope: existingEntry.scope,
            token_type: 'Bearer'
          })
        );
        return;
      }

      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unsupported_grant_type' }));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/v2/userinfo') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      const info = this.validTokens.get(token);
      if (!info) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Invalid or expired access token' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          sub: info.sub,
          name: info.name,
          given_name: 'Alex',
          family_name: 'Morgan',
          email: info.email
        })
      );
      return;
    }

    if (req.method === 'POST' && url.pathname === '/rest/posts') {
      const auth = req.headers.authorization || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
      const rawBody = await this.#readBody(req);
      let payload = null;
      try {
        payload = JSON.parse(rawBody);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Invalid JSON payload' }));
        return;
      }

      const requestRecord = {
        receivedAt: new Date().toISOString(),
        idempotencyKey: req.headers['x-idempotency-key'] || null,
        restliProtocol: req.headers['x-restli-protocol-version'] || null,
        linkedinVersion: req.headers['linkedin-version'] || null,
        author: payload?.author,
        commentary: payload?.commentary
      };
      this.postRequests.push(requestRecord);

      if (!token || !this.validTokens.has(token)) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Invalid or expired access token' }));
        return;
      }

      if (
        req.headers['x-restli-protocol-version'] !== '2.0.0' ||
        !req.headers['linkedin-version']
      ) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Missing required X-Restli-Protocol-Version or LinkedIn-Version header' }));
        return;
      }

      if (this.faultPlan.permanentErrorStatus) {
        const status = this.faultPlan.permanentErrorStatus;
        const msg =
          this.faultPlan.permanentErrorMessage ||
          `Simulated permanent LinkedIn error (HTTP ${status})`;
        this.faultPlan.permanentErrorStatus = null;
        this.faultPlan.permanentErrorMessage = null;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: msg }));
        return;
      }

      if (this.faultPlan.temporaryFailuresRemaining > 0) {
        this.faultPlan.temporaryFailuresRemaining -= 1;
        const status = this.faultPlan.temporaryStatus || 503;
        const headers = { 'Content-Type': 'application/json' };
        if (this.faultPlan.retryAfterSeconds !== null) {
          headers['Retry-After'] = String(this.faultPlan.retryAfterSeconds);
        }
        res.writeHead(status, headers);
        res.end(
          JSON.stringify({
            message: `Simulated temporary LinkedIn outage (HTTP ${status})`
          })
        );
        return;
      }

      if (!payload?.author || !payload?.commentary || payload?.lifecycleState !== 'PUBLISHED') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Invalid /rest/posts payload fields' }));
        return;
      }

      // Mirror LinkedIn's duplicate post detection
      const duplicate = this.createdPosts.find(
        (p) => p.author === payload.author && p.commentary === payload.commentary
      );
      if (duplicate) {
        res.writeHead(422, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Duplicate post rejected by LinkedIn API' }));
        return;
      }

      const urn = `urn:li:share:${crypto.randomBytes(6).toString('hex')}`;
      this.createdPosts.push({
        urn,
        author: payload.author,
        commentary: payload.commentary,
        visibility: payload.visibility,
        createdAt: new Date().toISOString()
      });

      res.writeHead(201, {
        'Content-Type': 'application/json',
        'x-restli-id': urn
      });
      res.end();
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Not found in Mock LinkedIn Server' }));
  }
}
