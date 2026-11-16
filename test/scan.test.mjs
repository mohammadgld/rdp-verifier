import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createScan } from '../src/scan.mjs';

test('scan honors the selected concurrency and keeps only verified matches', async () => {
  const targets = [1, 2, 3, 4, 5].map((port) => ({ host: '127.0.0.1', port }));
  let active = 0;
  let peak = 0;
  const scan = createScan(targets, {
    concurrency: 2,
    timeoutMs: 1000,
    probe: async (_host, port) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 15));
      active -= 1;
      return { ok: port === 2 || port === 5 };
    },
  });
  await scan.done;
  assert.equal(peak, 2);
  assert.equal(scan.status, 'done');
  assert.equal(scan.scanned, 5);
  assert.deepEqual(scan.matches, [targets[1], targets[4]]);
});

test('cancel stops new targets and releases in-flight probes', async () => {
  const targets = Array.from({ length: 10 }, (_, i) => ({ host: '127.0.0.1', port: i + 1 }));
  const scan = createScan(targets, {
    concurrency: 3,
    timeoutMs: 1000,
    probe: async (_host, _port, { signal }) => new Promise((resolve) => {
      signal.addEventListener('abort', () => resolve({ ok: false }), { once: true });
    }),
  });
  scan.cancel();
  assert.equal(scan.status, 'cancelling');
  await scan.done;
  assert.equal(scan.status, 'cancelled');
  assert.equal(scan.scanned, 0);
  assert.deepEqual(scan.matches, []);
  assert.deepEqual(scan.stats, {
    verified: 0, timeout: 0, notRdp: 0, authUnavailable: 0, connectionError: 0, other: 0,
  });
});

test('results already displayed during a scan keep their order at completion', async () => {
  const targets = [1, 2].map((port) => ({ host: '127.0.0.1', port }));
  const scan = createScan(targets, {
    concurrency: 2,
    timeoutMs: 1000,
    probe: async (_host, port) => {
      await new Promise((resolve) => setTimeout(resolve, port === 1 ? 40 : 5));
      return { ok: true };
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(scan.matches, [targets[1]]);
  await scan.done;
  assert.deepEqual(scan.matches, [targets[1], targets[0]]);
});

test('scan groups rejected targets into useful log counts', async () => {
  const targets = [1, 2, 3, 4, 5, 6].map((port) => ({ host: '127.0.0.1', port }));
  const outcomes = [
    { ok: true, reason: 'credssp-challenge' },
    { ok: false, reason: 'timeout' },
    { ok: false, reason: 'not-rdp' },
    { ok: false, reason: 'no-credssp' },
    { ok: false, reason: 'connect-error' },
    { ok: false, reason: 'unexpected' },
  ];
  const scan = createScan(targets, {
    concurrency: 2,
    timeoutMs: 1000,
    probe: async (_host, port) => outcomes[port - 1],
  });
  await scan.done;
  assert.deepEqual(scan.stats, {
    verified: 1,
    timeout: 1,
    notRdp: 1,
    authUnavailable: 1,
    connectionError: 1,
    other: 1,
  });
});

test('supports 3000 concurrent checks and counts completed targets exactly', async () => {
  const targets = Array.from({ length: 3001 }, (_, index) => ({ host: '127.0.0.1', port: index + 1 }));
  let active = 0;
  let peak = 0;
  const scan = createScan(targets, {
    concurrency: 3000,
    timeoutMs: 1000,
    probe: async (_host, port) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setImmediate(resolve));
      active -= 1;
      return port % 1000 === 0 ? { ok: true } : { ok: false, reason: 'connect-error' };
    },
  });
  await scan.done;
  assert.equal(peak, 3000);
  assert.equal(scan.total, 3001);
  assert.equal(scan.scanned, 3001);
  assert.equal(scan.matches.length, 3);
  assert.equal(scan.stats.verified, 3);
  assert.equal(Object.values(scan.stats).reduce((sum, count) => sum + count, 0), scan.scanned);
});
