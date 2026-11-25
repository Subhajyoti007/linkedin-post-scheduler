const LITTLE_TEXT_RESERVED = /[\\|{}@[\]()<>#*_~]/g;
const PRESERVED_TOKEN_REGEX =
  /@\[[^\]]+\]\(urn:li:(?:person|organization):[A-Za-z0-9_-]+\)|(^|[\s])(#[A-Za-z][A-Za-z0-9_]*)/g;

/**
 * Escapes LinkedIn Little Text Format reserved characters while keeping valid
 * interactive #hashtags and @[Name](urn:li:...) mentions unescaped.
 */

export function formatCommentaryForLinkedIn(rawText) {
  const input = String(rawText || '').replace(/\r\n/g, '\n');
  let result = '';
  let lastIndex = 0;

  for (const match of input.matchAll(PRESERVED_TOKEN_REGEX)) {
    const matchIndex = match.index ?? 0;
    const prefix = match[1] || '';
    const tokenStart = matchIndex + prefix.length;
    const token = match[2] || match[0];

    if (tokenStart > lastIndex) {
      const plainChunk = input.slice(lastIndex, tokenStart);
      result += plainChunk.replace(LITTLE_TEXT_RESERVED, (ch) => `\\${ch}`);
    }

    result += token;
    lastIndex = tokenStart + token.length;
  }

  if (lastIndex < input.length) {
    result += input.slice(lastIndex).replace(LITTLE_TEXT_RESERVED, (ch) => `\\${ch}`);
  }

  return result;
}

/**
 * Parses HTTP Retry-After header (seconds or HTTP-date) into milliseconds.
 */

export function parseRetryAfterMs(headerValue, nowMs = Date.now()) {
  if (!headerValue) return null;
  const trimmed = String(headerValue).trim();
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    return Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : null;
  }
  const timestampMs = Date.parse(trimmed);
  if (Number.isFinite(timestampMs)) {
    return Math.max(0, timestampMs - nowMs);
  }
  return null;
}

export class LinkedInApiError extends Error {
  constructor({
    message,
    httpStatus = null,
    errorCode = 'LINKEDIN_API_ERROR',
    temporary = false,
    retryAfterMs = null,
    isDuplicate = false,
    isAuthError = false
  }) {
    super(message);
    this.name = 'LinkedInApiError';
    this.httpStatus = httpStatus;
    this.errorCode = errorCode;
    this.temporary = temporary;
    this.retryAfterMs = retryAfterMs;
    this.isDuplicate = isDuplicate;
    this.isAuthError = isAuthError;
  }
}

function isTemporaryHttpStatus(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

function extractErrorMessage(bodyText, status) {
  if (!bodyText) return `LinkedIn API returned HTTP ${status}`;
  try {
    const parsed = JSON.parse(bodyText);
    return (
      parsed.error_description ||
      parsed.message ||
      parsed.error ||
      `LinkedIn API returned HTTP ${status}`
    );
  } catch {
    return bodyText.slice(0, 300);
  }
}

function decodeJwtPayload(jwt) {
  try {
    const parts = String(jwt || '').split('.');
    if (parts.length < 2) return null;
    const json = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/**
 * HTTP client for LinkedIn OAuth 2.0, OpenID /v2/userinfo, and REST /rest/posts.
 */

export class LinkedInClient {
  constructor({
    oauthBaseUrl = 'https://www.linkedin.com',
    apiBaseUrl = 'https://api.linkedin.com',
    apiVersion = '202610',
    timeoutMs = 15000,
    fetchImpl = fetch
  } = {}) {
    this.oauthBaseUrl = oauthBaseUrl.replace(/\/+$/, '');
    this.apiBaseUrl = apiBaseUrl.replace(/\/+$/, '');
    this.apiVersion = apiVersion;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  setBaseUrls({ oauthBaseUrl, apiBaseUrl }) {
    if (oauthBaseUrl) this.oauthBaseUrl = oauthBaseUrl.replace(/\/+$/, '');
    if (apiBaseUrl) this.apiBaseUrl = apiBaseUrl.replace(/\/+$/, '');
  }

  buildAuthorizationUrl({
    clientId,
    redirectUri,
    state,
    scopes = 'openid profile w_member_social'
  }) {
    const normalizedScopes = String(scopes || 'openid profile w_member_social')
      .trim()
      .split(/[\s,]+/)
      .filter(Boolean)
      .join(' ');
    const query = [
      ['response_type', 'code'],
      ['client_id', clientId],
      ['redirect_uri', redirectUri],
      ['state', state],
      ['scope', normalizedScopes]
    ]
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');
    return `${this.oauthBaseUrl}/oauth/v2/authorization?${query}`;
  }

  async exchangeCodeForTokens({ code, clientId, clientSecret, redirectUri }) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri
    });

    const response = await this.#request(`${this.oauthBaseUrl}/oauth/v2/accessToken`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: body.toString()
    });

    const text = await response.text();
    if (!response.ok) {
      throw new LinkedInApiError({
        message: extractErrorMessage(text, response.status),
        httpStatus: response.status,
        errorCode: 'OAUTH_TOKEN_EXCHANGE_FAILED',
        temporary: isTemporaryHttpStatus(response.status)
      });
    }

    const data = JSON.parse(text);
    if (!data.access_token) {
      throw new LinkedInApiError({
        message: 'LinkedIn OAuth response did not include an access_token.',
        httpStatus: response.status,
        errorCode: 'OAUTH_INVALID_RESPONSE',
        temporary: false
      });
    }

    const nowMs = Date.now();
    const expiresInSec = Number(data.expires_in) || 5184000;
    const refreshExpiresInSec = Number(data.refresh_token_expires_in) || null;

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null,
      idToken: data.id_token || null,
      tokenType: data.token_type || 'Bearer',
      scope: data.scope || null,
      expiresAt: new Date(nowMs + expiresInSec * 1000).toISOString(),
      refreshExpiresAt: refreshExpiresInSec
        ? new Date(nowMs + refreshExpiresInSec * 1000).toISOString()
        : null
    };
  }

  async refreshAccessToken({ refreshToken, clientId, clientSecret }) {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret
    });

    const response = await this.#request(`${this.oauthBaseUrl}/oauth/v2/accessToken`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json'
      },
      body: body.toString()
    });

    const text = await response.text();
    if (!response.ok) {
      throw new LinkedInApiError({
        message: extractErrorMessage(text, response.status),
        httpStatus: response.status,
        errorCode: 'OAUTH_REFRESH_FAILED',
        temporary: isTemporaryHttpStatus(response.status),
        isAuthError: response.status === 401 || response.status === 400
      });
    }

    const data = JSON.parse(text);
    const nowMs = Date.now();
    const expiresInSec = Number(data.expires_in) || 5184000;

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken,
      tokenType: data.token_type || 'Bearer',
      scope: data.scope || null,
      expiresAt: new Date(nowMs + expiresInSec * 1000).toISOString()
    };
  }

  async getUserInfo(accessToken, idToken = null) {
    const response = await this.#request(`${this.apiBaseUrl}/v2/userinfo`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });

    const text = await response.text();
    if (!response.ok) {
      if (response.status === 403) {
        if (idToken) {
          const decoded = decodeJwtPayload(idToken);
          if (decoded?.sub) {
            return {
              sub: decoded.sub,
              authorUrn: `urn:li:person:${decoded.sub}`,
              name: decoded.name || [decoded.given_name, decoded.family_name].filter(Boolean).join(' ') || null,
              email: decoded.email || null,
              picture: decoded.picture || null
            };
          }
        }
        const legacy = await this.#tryGetLegacyProfile(accessToken);
        if (legacy) return legacy;
      }

      throw new LinkedInApiError({
        message: extractErrorMessage(text, response.status),
        httpStatus: response.status,
        errorCode: 'USERINFO_FAILED',
        temporary: isTemporaryHttpStatus(response.status),
        isAuthError: response.status === 401
      });
    }

    const profile = JSON.parse(text);
    if (!profile.sub) {
      throw new LinkedInApiError({
        message: 'LinkedIn userinfo response is missing member "sub" identifier.',
        httpStatus: response.status,
        errorCode: 'USERINFO_MISSING_SUB',
        temporary: false
      });
    }

    return {
      sub: profile.sub,
      authorUrn: `urn:li:person:${profile.sub}`,
      name: profile.name || [profile.given_name, profile.family_name].filter(Boolean).join(' ') || null,
      email: profile.email || null,
      picture: profile.picture || null
    };
  }

  async #tryGetLegacyProfile(accessToken) {
    const response = await this.#request(`${this.apiBaseUrl}/v2/me`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json'
      }
    });
    if (!response.ok) return null;
    const me = JSON.parse(await response.text());
    if (!me?.id) return null;
    const name = [me.localizedFirstName, me.localizedLastName].filter(Boolean).join(' ') || null;
    return {
      sub: me.id,
      authorUrn: `urn:li:person:${me.id}`,
      name,
      email: null,
      picture: null
    };
  }

  async publishPost({ accessToken, authorUrn, content, visibility = 'PUBLIC', idempotencyKey }) {
    const payload = {
      author: authorUrn,
      commentary: formatCommentaryForLinkedIn(content),
      visibility,
      distribution: {
        feedDistribution: 'MAIN_FEED',
        targetEntities: [],
        thirdPartyDistributionChannels: []
      },
      lifecycleState: 'PUBLISHED',
      isReshareDisabledByAuthor: false
    };

    const headers = {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0',
      'LinkedIn-Version': this.apiVersion
    };
    if (idempotencyKey) {
      headers['X-Idempotency-Key'] = idempotencyKey;
    }

    const response = await this.#request(`${this.apiBaseUrl}/rest/posts`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });

    const text = await response.text();
    if (response.status === 201 || response.status === 200 || response.status === 202) {
      let parsedUrn = response.headers.get('x-restli-id') || response.headers.get('x-linkedin-id');
      if (!parsedUrn && text) {
        try {
          const bodyJson = JSON.parse(text);
          parsedUrn = bodyJson.id || bodyJson.urn || null;
        } catch {
          // Empty or non-JSON body on 201 Created is standard for /rest/posts
        }
      }
      return {
        httpStatus: response.status,
        urn: parsedUrn || `urn:li:share:created-${Date.now()}`
      };
    }

    const message = extractErrorMessage(text, response.status);
    const temporary = isTemporaryHttpStatus(response.status);
    const retryAfterMs = parseRetryAfterMs(response.headers.get('retry-after'));
    const isDuplicate =
      response.status === 422 && /duplicate|already exists/i.test(message);

    throw new LinkedInApiError({
      message,
      httpStatus: response.status,
      errorCode: isDuplicate
        ? 'LINKEDIN_DUPLICATE_REJECTED'
        : temporary
          ? 'TEMPORARY_HTTP_ERROR'
          : response.status === 401
            ? 'UNAUTHORIZED'
            : 'PERMANENT_HTTP_ERROR',
      temporary,
      retryAfterMs,
      isDuplicate,
      isAuthError: response.status === 401
    });
  }

  async #request(url, options) {
    try {
      return await this.fetchImpl(url, {
        ...options,
        signal: AbortSignal.timeout(this.timeoutMs)
      });
    } catch (err) {
      throw new LinkedInApiError({
        message: `Network error calling LinkedIn API: ${err.message}`,
        httpStatus: null,
        errorCode: err.name === 'TimeoutError' || err.name === 'AbortError' ? 'TIMEOUT' : 'NETWORK_ERROR',
        temporary: true
      });
    }
  }
}
