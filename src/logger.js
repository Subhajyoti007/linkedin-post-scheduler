import fs from 'node:fs';
import path from 'node:path';

const LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

const SENSITIVE_KEY_PATTERN =
  /^(access_?token|refresh_?token|client_?secret|token_?encryption_?key|authorization|cookie|password|secret|oauth_?code|auth_?code)$/i;

/**
 * Recursively scrubs credentials, tokens, and authorization values before logging.
 */
export function redactSecrets(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return value.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]');
  }
  if (typeof value !== 'object') return value;
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactSecrets(value.message),
      code: value.code
    };
  }
  if (seen.has(value)) return '[Circular]';
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item, seen));
  }

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEY_PATTERN.test(k)) {
      out[k] = v ? '[REDACTED]' : null;
    } else {
      out[k] = redactSecrets(v, seen);
    }
  }
  return out;
}

/**
 * Structured JSON logger persisting to stdout, rotating log file, and SQLite app_logs.
 */
export class AppLogger {
  constructor({ level = 'info', logFilePath = null, silent = false, dbSink = null } = {}) {
    this.minLevel = LEVELS[level] ?? LEVELS.info;
    this.logFilePath = logFilePath;
    this.silent = silent;
    this.dbSink = dbSink;

    if (this.logFilePath) {
      fs.mkdirSync(path.dirname(this.logFilePath), { recursive: true });
    }
  }

  setDbSink(fn) {
    this.dbSink = fn;
  }

  log(level, component, event, message, meta = null, postId = null) {
    const numericLevel = LEVELS[level] ?? LEVELS.info;
    if (numericLevel < this.minLevel) return;

    const timestamp = new Date().toISOString();
    const safeMeta = meta ? redactSecrets(meta) : null;
    const safeMessage = redactSecrets(String(message));

    const entry = {
      timestamp,
      level,
      component,
      event,
      postId: postId || undefined,
      message: safeMessage,
      meta: safeMeta || undefined
    };

    if (!this.silent) {
      const line = JSON.stringify(entry);
      if (level === 'error') {
        process.stderr.write(line + '\n');
      } else {
        process.stdout.write(line + '\n');
      }
    }

    if (this.logFilePath) {
      try {
        fs.appendFileSync(this.logFilePath, JSON.stringify(entry) + '\n', 'utf8');
      } catch {
        // Ignore file sink failures to avoid interrupting background scheduling
      }
    }

    if (this.dbSink) {
      try {
        this.dbSink({
          level,
          component,
          event,
          postId,
          message: safeMessage,
          metaJson: safeMeta ? JSON.stringify(safeMeta) : null,
          createdAt: timestamp
        });
      } catch {
        // Never allow logging failure to crash request or worker execution
      }
    }
  }

  debug(component, event, message, meta = null, postId = null) {
    this.log('debug', component, event, message, meta, postId);
  }

  info(component, event, message, meta = null, postId = null) {
    this.log('info', component, event, message, meta, postId);
  }

  warn(component, event, message, meta = null, postId = null) {
    this.log('warn', component, event, message, meta, postId);
  }

  error(component, event, message, meta = null, postId = null) {
    this.log('error', component, event, message, meta, postId);
  }
}
