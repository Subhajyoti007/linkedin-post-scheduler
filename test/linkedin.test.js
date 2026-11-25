import test from 'node:test';
import assert from 'node:assert/strict';
import { formatCommentaryForLinkedIn, parseRetryAfterMs } from '../src/linkedin.js';
import { computeRetryDelayMs } from '../src/worker.js';
import { redactSecrets } from '../src/logger.js';

test('formatCommentaryForLinkedIn escapes reserved chars while preserving hashtags & mentions', () => {
  const raw = 'Launch v2 (beta) [2026] *fast* #AI_Agents and @[Jane Doe](urn:li:person:abc_1)';
  const formatted = formatCommentaryForLinkedIn(raw);

  assert.ok(formatted.includes('\\(beta\\)'));
  assert.ok(formatted.includes('\\[2026\\]'));
  assert.ok(formatted.includes('\\*fast\\*'));
  assert.ok(formatted.includes('#AI_Agents'), 'Hashtags should remain interactive');
  assert.ok(formatted.includes('@[Jane Doe](urn:li:person:abc_1)'), 'Mentions should stay intact');
});

test('parseRetryAfterMs handles numeric seconds and HTTP dates', () => {
  assert.equal(parseRetryAfterMs('12'), 12000);
  const now = Date.UTC(2026, 10, 25, 10, 0, 0);
  const futureDate = new Date(now + 15000).toUTCString();
  assert.equal(parseRetryAfterMs(futureDate, now), 15000);
  assert.equal(parseRetryAfterMs('invalid'), null);
});

test('computeRetryDelayMs increases exponentially and honors larger Retry-After', () => {
  const d1 = computeRetryDelayMs({ attemptNumber: 1, baseDelayMs: 1000, maxDelayMs: 60000 });
  const d2 = computeRetryDelayMs({ attemptNumber: 2, baseDelayMs: 1000, maxDelayMs: 60000 });
  const d3 = computeRetryDelayMs({ attemptNumber: 3, baseDelayMs: 1000, maxDelayMs: 60000 });
  const d4 = computeRetryDelayMs({ attemptNumber: 4, baseDelayMs: 1000, maxDelayMs: 60000 });

  assert.equal(d1, 1000);
  assert.equal(d2, 2000);
  assert.equal(d3, 4000);
  assert.equal(d4, 8000);
  assert.ok(d2 > d1 && d3 > d2 && d4 > d3);

  const honored = computeRetryDelayMs({
    attemptNumber: 1,
    baseDelayMs: 1000,
    maxDelayMs: 60000,
    retryAfterMs: 5000
  });
  assert.equal(honored, 5000);
});

test('redactSecrets scrubs credentials and Bearer tokens without hiding error codes', () => {
  const scrubbed = redactSecrets({
    accessToken: 'secret-tok',
    client_secret: 'super-secret',
    authorization: 'Bearer abc.def.ghi',
    errorCode: 'TEMPORARY_HTTP_ERROR',
    httpStatus: 503,
    message: 'Failed with Bearer xyz123'
  });

  assert.equal(scrubbed.accessToken, '[REDACTED]');
  assert.equal(scrubbed.client_secret, '[REDACTED]');
  assert.equal(scrubbed.authorization, '[REDACTED]');
  assert.equal(scrubbed.errorCode, 'TEMPORARY_HTTP_ERROR');
  assert.equal(scrubbed.httpStatus, 503);
  assert.equal(scrubbed.message, 'Failed with Bearer [REDACTED]');
});
