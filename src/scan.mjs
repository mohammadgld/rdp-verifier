import { probeRdp } from './rdp.mjs';
import { setMaxListeners } from 'node:events';

function category(reason) {
  if (reason === 'timeout') return 'timeout';
  if (reason === 'not-rdp' || reason === 'invalid-rdp') return 'notRdp';
  if (['no-credssp', 'tls-error', 'invalid-challenge', 'oversized-challenge'].includes(reason)) return 'authUnavailable';
  if (reason === 'connect-error' || reason === 'closed') return 'connectionError';
  return 'other';
}

export function createScan(targets, { concurrency = 32, timeoutMs = 3000, probe = probeRdp } = {}) {
  if (!Array.isArray(targets) || !Number.isInteger(concurrency) || concurrency < 1 || concurrency > 3000) {
    throw new Error('Concurrent checks must be between 1 and 3000.');
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 500 || timeoutMs > 10_000) {
    throw new Error('Connection timeout must be between 500 and 10000 ms.');
  }

  const controller = new AbortController();
  setMaxListeners(0, controller.signal);
  let next = 0;
  const scan = {
    status: 'running',
    total: targets.length,
    scanned: 0,
    matches: [],
    stats: { verified: 0, timeout: 0, notRdp: 0, authUnavailable: 0, connectionError: 0, other: 0 },
    cancel() {
      if (scan.status === 'running') {
        scan.status = 'cancelling';
        controller.abort();
      }
    },
  };

  async function worker() {
    while (!controller.signal.aborted) {
      const index = next++;
      if (index >= targets.length) return;
      const target = targets[index];
      let completed = false;
      try {
        const result = await probe(target.host, target.port, { timeoutMs, signal: controller.signal });
        if (!controller.signal.aborted && result.ok) {
          scan.matches.push(target);
          scan.stats.verified += 1;
          completed = true;
        } else if (!controller.signal.aborted) {
          scan.stats[category(result.reason)] += 1;
          completed = true;
        }
      } catch {
        // A failed target is excluded; the remaining scan continues.
        if (!controller.signal.aborted) {
          scan.stats.other += 1;
          completed = true;
        }
      }
      if (completed) scan.scanned += 1;
    }
  }

  scan.done = Promise.all(Array.from({ length: Math.min(concurrency, targets.length) }, worker))
    .then(() => {
      if (scan.status === 'running') scan.status = 'done';
      else if (scan.status === 'cancelling') scan.status = 'cancelled';
      return scan;
    });
  return scan;
}
