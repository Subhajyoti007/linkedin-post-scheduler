import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig } from './config.js';
import { TokenCipher } from './crypto.js';
import { AppLogger } from './logger.js';
import { AppDatabase } from './db.js';
import { LinkedInClient } from './linkedin.js';
import { PostWorker } from './worker.js';
import { AppServer } from './server.js';
import { MockLinkedInServer } from './mock-linkedin.js';

/**
 * Bootstraps and coordinates the application lifecycle.
 * Can be called programmatically in tests with custom config overrides.
 */

export async function startApplication(configOverrides = {}) {
  const config = loadConfig(configOverrides);
  const cipher = new TokenCipher({
    tokenEncryptionKey: config.tokenEncryptionKey,
    masterKeyPath: config.masterKeyPath
  });

  const logger = new AppLogger({
    level: config.logLevel,
    logFilePath: config.logFilePath,
    silent: config.silentLogs
  });

  const db = new AppDatabase({
    databasePath: config.databasePath,
    cipher
  });

  logger.setDbSink((entry) => db.insertLog(entry));

  if (cipher.keySource === 'generated-file') {
    logger.warn(
      'crypto',
      'MASTER_KEY_GENERATED',
      'Generated local AES-256-GCM key file because TOKEN_ENCRYPTION_KEY was not set. Set TOKEN_ENCRYPTION_KEY in production.',
      { masterKeyPath: config.masterKeyPath }
    );
  }

  // Optional pre-seeding from .env when DB does not have credentials yet
  
  const existingOAuth = db.getOAuthConfigStatus();
  if (!existingOAuth.configured && config.linkedinClientId && config.linkedinClientSecret) {
    db.saveOAuthConfig({
      clientId: config.linkedinClientId,
      clientSecret: config.linkedinClientSecret,
      redirectUri: config.linkedinRedirectUri
    });
    logger.info('oauth', 'OAUTH_CONFIG_SEEDED', 'Loaded initial LinkedIn OAuth credentials from environment.');
  }

  let mockServer = null;
  let oauthBaseUrl = config.linkedinOAuthBaseUrl;
  let apiBaseUrl = config.linkedinApiBaseUrl;

  if (config.linkedinMode === 'mock') {
    mockServer = new MockLinkedInServer({ host: '127.0.0.1', port: 0 });
    const mockUrl = await mockServer.start();
    oauthBaseUrl = mockUrl;
    apiBaseUrl = mockUrl;
    logger.info('server', 'MOCK_LINKEDIN_STARTED', `Mock LinkedIn sandbox listening on ${mockUrl}`);
  }

  const linkedinClient = new LinkedInClient({
    oauthBaseUrl,
    apiBaseUrl,
    apiVersion: config.linkedinApiVersion,
    timeoutMs: config.httpTimeoutMs
  });

  const worker = new PostWorker({
    db,
    linkedinClient,
    logger,
    pollIntervalMs: config.workerPollIntervalMs,
    lockTimeoutMs: config.workerLockTimeoutMs,
    maxRetryAttempts: config.maxRetryAttempts,
    retryBaseDelayMs: config.retryBaseDelayMs,
    retryMaxDelayMs: config.retryMaxDelayMs
  });

  const server = new AppServer({
    host: config.host,
    port: config.port,
    config,
    db,
    linkedinClient,
    worker,
    logger,
    mockServer
  });

  const baseUrl = await server.start();
  worker.start();

  return {
    config,
    cipher,
    logger,
    db,
    linkedinClient,
    worker,
    server,
    mockServer,
    baseUrl,
    async stop() {
      await worker.stop();
      await server.stop();
      if (mockServer) await mockServer.stop();
      db.close();
    }
  };
}

const isMain =
  Boolean(process.argv[1]) &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const app = await startApplication();
  console.log(`\nLinkedIn Post Scheduler running at ${app.baseUrl} [mode: ${app.config.linkedinMode}]`);

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.logger.info('server', 'SHUTDOWN_SIGNAL', `Received ${signal}, shutting down gracefully...`);
    await app.stop();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}
