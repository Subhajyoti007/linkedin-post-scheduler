import { generateRandomToken } from './crypto.js';
import { LinkedInApiError } from './linkedin.js';

/**
 * Computes strictly increasing exponential backoff delay, honoring any larger Retry-After header.
 */

export function computeRetryDelayMs({
  attemptNumber,
  baseDelayMs,
  maxDelayMs,
  retryAfterMs = null
}) {
  const exponential = Math.min(
    maxDelayMs,
    baseDelayMs * Math.pow(2, Math.max(0, attemptNumber - 1))
  );
  if (typeof retryAfterMs === 'number' && retryAfterMs > 0) {
    return Math.max(exponential, Math.min(maxDelayMs, retryAfterMs));
  }
  return exponential;
}

/**
 * Background worker that claims due scheduled posts, publishes via LinkedIn API,
 * retries temporary errors with increasing delays, and guarantees zero duplicate posts.
 */

export class PostWorker {
  constructor({
    db,
    linkedinClient,
    logger,
    pollIntervalMs = 1000,
    lockTimeoutMs = 120000,
    maxRetryAttempts = 5,
    retryBaseDelayMs = 5000,
    retryMaxDelayMs = 300000,
    workerId = `worker-${generateRandomToken(4)}`
  }) {
    this.db = db;
    this.linkedinClient = linkedinClient;
    this.logger = logger;
    this.pollIntervalMs = pollIntervalMs;
    this.lockTimeoutMs = lockTimeoutMs;
    this.maxRetryAttempts = maxRetryAttempts;
    this.retryBaseDelayMs = retryBaseDelayMs;
    this.retryMaxDelayMs = retryMaxDelayMs;
    this.workerId = workerId;

    this.#running = false;
    this.#timer = null;
    this.#activeTick = null;
    this.lastTickAt = null;
    this.processedCount = 0;
  }

  #running;
  #timer;
  #activeTick;

  start() {
    if (this.#running) return;
    this.#running = true;

    const recovered = this.db.recoverStaleProcessingPosts({
      lockTimeoutMs: this.lockTimeoutMs
    });
    if (recovered.length > 0) {
      this.logger.warn(
        'worker',
        'STALE_LOCKS_RECOVERED',
        `Recovered ${recovered.length} interrupted processing post(s) as failed to prevent duplicate posts.`,
        { postIds: recovered }
      );
    }

    this.logger.info('worker', 'WORKER_STARTED', 'Background post scheduler started.', {
      workerId: this.workerId,
      pollIntervalMs: this.pollIntervalMs,
      retryBaseDelayMs: this.retryBaseDelayMs,
      maxRetryAttempts: this.maxRetryAttempts
    });

    this.#scheduleNextTick(0);
  }

  async stop() {
    this.#running = false;
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    if (this.#activeTick) {
      await this.#activeTick;
    }
    this.logger.info('worker', 'WORKER_STOPPED', 'Background post scheduler stopped.', {
      workerId: this.workerId
    });
  }

  getStatus() {
    return {
      running: this.#running,
      workerId: this.workerId,
      pollIntervalMs: this.pollIntervalMs,
      retryBaseDelayMs: this.retryBaseDelayMs,
      retryMaxDelayMs: this.retryMaxDelayMs,
      maxRetryAttempts: this.maxRetryAttempts,
      lastTickAt: this.lastTickAt,
      processedCount: this.processedCount
    };
  }

  #scheduleNextTick(delayMs) {
    if (!this.#running) return;
    this.#timer = setTimeout(async () => {
      try {
        await this.runOnce();
      } catch (err) {
        this.logger.error('worker', 'TICK_ERROR', `Worker tick error: ${err.message}`, {
          error: err
        });
      } finally {
        if (this.#running) {
          this.#scheduleNextTick(this.pollIntervalMs);
        }
      }
    }, delayMs);
    this.#timer.unref?.();
  }

  /**
   * Processes all currently due scheduled posts. Safe against concurrent re-entry.
   */
  
  async runOnce(nowMs = Date.now()) {
    if (this.#activeTick) {
      return this.#activeTick;
    }

    this.#activeTick = this.#processDuePosts(nowMs);
    try {
      return await this.#activeTick;
    } finally {
      this.#activeTick = null;
    }
  }

  async #processDuePosts(nowMs) {
    this.lastTickAt = new Date(nowMs).toISOString();
    let handled = 0;

    while (true) {
      const claimNowIso = new Date(Math.max(Date.now(), nowMs)).toISOString();
      const post = this.db.claimNextDuePost({
        workerId: this.workerId,
        nowIso: claimNowIso
      });
      if (!post) break;

      await this.#executeClaimedPost(post);
      handled += 1;
      this.processedCount += 1;
    }

    return handled;
  }

  async #executeClaimedPost(post) {
    const startMs = Date.now();
    const attemptNumber = post.attemptCount;

    // Defense-in-depth duplicate protection before making any external network call
    
    if (post.publishedPostUrn) {
      this.logger.warn(
        'worker',
        'DUPLICATE_PREVENTED',
        'Skipped publish attempt because post already has a published LinkedIn URN.',
        { publishedPostUrn: post.publishedPostUrn },
        post.id
      );
      return;
    }

    this.logger.info(
      'worker',
      'POST_PROCESSING_STARTED',
      `Processing scheduled post (attempt ${attemptNumber}/${post.maxAttempts}).`,
      {
        attemptNumber,
        maxAttempts: post.maxAttempts,
        scheduledAt: post.scheduledAt
      },
      post.id
    );

    try {
      let tokens = this.db.getDecryptedOAuthTokens();
      if (!tokens) {
        throw new LinkedInApiError({
          message: 'LinkedIn account is not connected. Connect LinkedIn OAuth before publishing.',
          errorCode: 'NO_OAUTH_CONNECTION',
          temporary: false,
          isAuthError: true
        });
      }

      if (tokens.authorUrn !== post.authorUrn) {
        throw new LinkedInApiError({
          message: `Connected account (${tokens.authorUrn}) does not match post author (${post.authorUrn}).`,
          errorCode: 'AUTHOR_MISMATCH',
          temporary: false,
          isAuthError: true
        });
      }

      // Refresh token proactively if expired and refresh_token is available
      
      if (tokens.expiresAt <= new Date().toISOString()) {
        tokens = await this.#tryRefreshToken(tokens, post.id);
      }

      let result;
      try {
        result = await this.linkedinClient.publishPost({
          accessToken: tokens.accessToken,
          authorUrn: post.authorUrn,
          content: post.content,
          visibility: post.visibility,
          idempotencyKey: post.idempotencyKey
        });
      } catch (err) {
        if (err instanceof LinkedInApiError && err.isAuthError && tokens.refreshToken) {
          const refreshed = await this.#tryRefreshToken(tokens, post.id);
          result = await this.linkedinClient.publishPost({
            accessToken: refreshed.accessToken,
            authorUrn: post.authorUrn,
            content: post.content,
            visibility: post.visibility,
            idempotencyKey: post.idempotencyKey
          });
        } else {
          throw err;
        }
      }

      const durationMs = Date.now() - startMs;
      this.db.markPostPublished({
        postId: post.id,
        workerId: this.workerId,
        publishedPostUrn: result.urn,
        attemptNumber,
        httpStatus: result.httpStatus,
        durationMs
      });

      this.logger.info(
        'worker',
        'POST_PUBLISHED',
        `Post published to LinkedIn (${result.urn}).`,
        {
          attemptNumber,
          httpStatus: result.httpStatus,
          publishedPostUrn: result.urn,
          durationMs
        },
        post.id
      );
    } catch (err) {
      const durationMs = Date.now() - startMs;
      const apiErr =
        err instanceof LinkedInApiError
          ? err
          : new LinkedInApiError({
              message: err.message || 'Unexpected error during publish.',
              errorCode: 'UNEXPECTED_ERROR',
              temporary: false
            });

      if (apiErr.temporary && attemptNumber < post.maxAttempts) {
        const retryDelayMs = computeRetryDelayMs({
          attemptNumber,
          baseDelayMs: this.retryBaseDelayMs,
          maxDelayMs: this.retryMaxDelayMs,
          retryAfterMs: apiErr.retryAfterMs
        });
        const nextAttemptAt = new Date(Date.now() + retryDelayMs).toISOString();

        this.db.schedulePostRetry({
          postId: post.id,
          workerId: this.workerId,
          attemptNumber,
          httpStatus: apiErr.httpStatus,
          errorCode: apiErr.errorCode,
          errorMessage: apiErr.message,
          retryDelayMs,
          nextAttemptAt,
          durationMs
        });

        this.logger.warn(
          'worker',
          'POST_RETRY_SCHEDULED',
          `Temporary error on attempt ${attemptNumber}/${post.maxAttempts}; retrying in ${retryDelayMs}ms.`,
          {
            attemptNumber,
            maxAttempts: post.maxAttempts,
            httpStatus: apiErr.httpStatus,
            errorCode: apiErr.errorCode,
            errorMessage: apiErr.message,
            retryDelayMs,
            nextAttemptAt
          },
          post.id
        );
        return;
      }

      const finalCode =
        apiErr.temporary && attemptNumber >= post.maxAttempts
          ? 'MAX_RETRIES_EXCEEDED'
          : apiErr.errorCode;

      const finalOutcome = apiErr.isDuplicate
        ? 'skipped_duplicate'
        : apiErr.temporary
          ? 'temporary_error'
          : 'permanent_error';

      this.db.markPostFailed({
        postId: post.id,
        workerId: this.workerId,
        attemptNumber,
        outcome: finalOutcome,
        httpStatus: apiErr.httpStatus,
        errorCode: finalCode,
        errorMessage: apiErr.message,
        durationMs
      });

      this.logger.error(
        'worker',
        'POST_FAILED',
        `Post permanently marked failed on attempt ${attemptNumber}/${post.maxAttempts}: ${apiErr.message}`,
        {
          attemptNumber,
          httpStatus: apiErr.httpStatus,
          errorCode: finalCode,
          outcome: finalOutcome,
          durationMs
        },
        post.id
      );
    }
  }

  async #tryRefreshToken(tokens, postId) {
    if (!tokens.refreshToken) {
      throw new LinkedInApiError({
        message: 'LinkedIn OAuth access token expired and no refresh token is available. Please reconnect.',
        httpStatus: 401,
        errorCode: 'TOKEN_EXPIRED',
        temporary: false,
        isAuthError: true
      });
    }

    const oauthConfig = this.db.getDecryptedOAuthConfig();
    if (!oauthConfig) {
      throw new LinkedInApiError({
        message: 'LinkedIn OAuth client configuration is missing; cannot refresh expired token.',
        errorCode: 'OAUTH_CONFIG_MISSING',
        temporary: false
      });
    }

    this.logger.info('oauth', 'TOKEN_REFRESH_ATTEMPT', 'Refreshing expired LinkedIn access token.', null, postId);
    const refreshed = await this.linkedinClient.refreshAccessToken({
      refreshToken: tokens.refreshToken,
      clientId: oauthConfig.clientId,
      clientSecret: oauthConfig.clientSecret
    });

    this.db.saveOAuthTokens({
      authorUrn: tokens.authorUrn,
      memberSub: tokens.memberSub,
      memberName: tokens.memberName,
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      tokenType: refreshed.tokenType,
      scope: refreshed.scope || tokens.scope,
      expiresAt: refreshed.expiresAt
    });

    this.logger.info('oauth', 'TOKEN_REFRESH_SUCCEEDED', 'LinkedIn access token refreshed securely.', null, postId);
    return this.db.getDecryptedOAuthTokens();
  }
}
