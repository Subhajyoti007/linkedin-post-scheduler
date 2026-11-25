import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = path.resolve(__dirname, '..');

/**
 * Parses a .env file without overriding already-set process.env variables.
 */
function loadDotEnv(envPath) {
  if (!fs.existsSync(envPath)) return;
  const raw = fs.readFileSync(envPath, 'utf8');
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eqIdx = line.indexOf('=');
    if (eqIdx <= 0) continue;
    const key = line.slice(0, eqIdx).trim();
    let value = line.slice(eqIdx + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function parseIntEnv(value, fallback, min = 0) {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < min) return fallback;
  return parsed;
}

function resolveProjectPath(targetPath) {
  return path.isAbsolute(targetPath)
    ? targetPath
    : path.resolve(PROJECT_ROOT, targetPath);
}

/**
 * Loads application configuration from environment variables and .env file.
 */
export function loadConfig(overrides = {}) {
  loadDotEnv(path.join(PROJECT_ROOT, '.env'));

  const args = new Set(process.argv.slice(2));
  const modeFromArgs = args.has('--mock') ? 'mock' : undefined;
  const mode = (
    overrides.linkedinMode ||
    modeFromArgs ||
    process.env.LINKEDIN_MODE ||
    'live'
  ).toLowerCase();

  if (mode !== 'live' && mode !== 'mock') {
    throw new Error(`Invalid LINKEDIN_MODE "${mode}". Expected "live" or "mock".`);
  }

  const port = overrides.port ?? parseIntEnv(process.env.PORT, 3000, 0);
  const host = overrides.host || process.env.HOST || '127.0.0.1';
  const dbPath = resolveProjectPath(
    overrides.databasePath || process.env.DATABASE_PATH || '.data/app.db'
  );
  const logFilePath = resolveProjectPath(
    overrides.logFilePath || process.env.LOG_FILE_PATH || '.data/logs/app.log'
  );
  const masterKeyPath = resolveProjectPath(
    overrides.masterKeyPath || path.join(path.dirname(dbPath), '.master.key')
  );

  const defaultRedirectUri =
    port > 0
      ? `http://localhost:${port}/auth/linkedin/callback`
      : 'http://localhost:3000/auth/linkedin/callback';

  return {
    port,
    host,
    linkedinMode: mode,
    linkedinApiVersion: overrides.linkedinApiVersion || process.env.LINKEDIN_API_VERSION || '202610',
    linkedinOAuthBaseUrl:
      overrides.linkedinOAuthBaseUrl ||
      process.env.LINKEDIN_OAUTH_BASE_URL ||
      'https://www.linkedin.com',
    linkedinApiBaseUrl:
      overrides.linkedinApiBaseUrl ||
      process.env.LINKEDIN_API_BASE_URL ||
      'https://api.linkedin.com',
    linkedinRedirectUri:
      overrides.linkedinRedirectUri ||
      process.env.LINKEDIN_REDIRECT_URI ||
      defaultRedirectUri,
    linkedinClientId: overrides.linkedinClientId ?? process.env.LINKEDIN_CLIENT_ID ?? '',
    linkedinClientSecret:
      overrides.linkedinClientSecret ?? process.env.LINKEDIN_CLIENT_SECRET ?? '',
    tokenEncryptionKey:
      overrides.tokenEncryptionKey ?? process.env.TOKEN_ENCRYPTION_KEY ?? '',
    masterKeyPath,
    databasePath: dbPath,
    logFilePath,
    logLevel: (overrides.logLevel || process.env.LOG_LEVEL || 'info').toLowerCase(),
    workerPollIntervalMs:
      overrides.workerPollIntervalMs ??
      parseIntEnv(process.env.WORKER_POLL_INTERVAL_MS, 1000, 50),
    workerLockTimeoutMs:
      overrides.workerLockTimeoutMs ??
      parseIntEnv(process.env.WORKER_LOCK_TIMEOUT_MS, 120000, 1000),
    maxRetryAttempts:
      overrides.maxRetryAttempts ??
      parseIntEnv(process.env.MAX_RETRY_ATTEMPTS, 5, 1),
    retryBaseDelayMs:
      overrides.retryBaseDelayMs ??
      parseIntEnv(process.env.RETRY_BASE_DELAY_MS, 5000, 10),
    retryMaxDelayMs:
      overrides.retryMaxDelayMs ??
      parseIntEnv(process.env.RETRY_MAX_DELAY_MS, 300000, 50),
    httpTimeoutMs:
      overrides.httpTimeoutMs ??
      parseIntEnv(process.env.HTTP_TIMEOUT_MS, 15000, 100),
    silentLogs: Boolean(overrides.silentLogs)
  };
}
