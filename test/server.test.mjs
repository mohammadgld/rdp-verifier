import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { startServer } from '../server.mjs';

test('local API serves the UI, validates input and returns only accepted targets', async () => {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'rdp-check-test-'));
  const app = await startServer({ port: 0, openBrowser: false, outputDirectory });
  const base = `http://127.0.0.1:${app.port}`;
  try {
    const page = await fetch(base);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /RDP Verifier/);

    const invalid = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: 'bad host', concurrency: 2, timeoutMs: 500 }),
    });
    assert.equal(invalid.status, 400);

    const foreign = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://example.org' },
      body: JSON.stringify({ input: '127.0.0.1:1', concurrency: 1, timeoutMs: 500 }),
    });
    assert.equal(foreign.status, 403);

    const started = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: '127.0.0.1:1', concurrency: 1, timeoutMs: 500 }),
    });
    assert.equal(started.status, 201);
    const { id, total } = await started.json();
    assert.equal(total, 1);

    let snapshot;
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const response = await fetch(`${base}/api/scans/${id}`);
      assert.equal(response.status, 200);
      snapshot = await response.json();
      if (snapshot.status === 'done') break;
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    assert.equal(snapshot.status, 'done');
    assert.equal(snapshot.scanned, 1);
    assert.deepEqual(snapshot.matches, []);
    assert.equal(snapshot.outputError, null);
    assert.ok(snapshot.outputFile.startsWith(outputDirectory));
    assert.equal(await readFile(snapshot.outputFile, 'utf8'), '');
    assert.equal((await readdir(outputDirectory)).length, 1);
    assert.deepEqual(Object.keys(snapshot.stats).sort(), [
      'authUnavailable', 'connectionError', 'notRdp', 'other', 'timeout', 'verified',
    ]);
  } finally {
    await app.close();
    assert.ok(outputDirectory.startsWith(join(tmpdir(), 'rdp-check-test-')));
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('accepts a request body larger than four MiB without a file-size rejection', async () => {
  const app = await startServer({ port: 0, openBrowser: false });
  try {
    const response = await fetch(`http://127.0.0.1:${app.port}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        input: `127.0.0.1:1\n#${'x'.repeat(5 * 1024 * 1024)}`,
        concurrency: 0,
        timeoutMs: 3000,
      }),
    });
    assert.equal(response.status, 400);
    const data = await response.json();
    assert.match(data.error, /concurrent/i);
  } finally {
    await app.close();
  }
});

test('writes only verified targets to Desktop output and supports incremental results', async () => {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'rdp-check-test-'));
  const app = await startServer({
    port: 0,
    openBrowser: false,
    outputDirectory,
    probe: async (_host, port) => ({ ok: port === 1 || port === 3, reason: 'connect-error' }),
  });
  const base = `http://127.0.0.1:${app.port}`;
  try {
    const response = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: '127.0.0.1:1\n127.0.0.1:2\n127.0.0.1:3', concurrency: 2, timeoutMs: 500 }),
    });
    assert.equal(response.status, 201);
    const { id } = await response.json();
    let full;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      full = await (await fetch(`${base}/api/scans/${id}`)).json();
      if (full.status === 'done') break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(full.status, 'done');
    assert.equal(full.scanned, 3);
    assert.equal(full.verifiedCount, 2);
    assert.deepEqual(full.matches, [
      { host: '127.0.0.1', port: 1 },
      { host: '127.0.0.1', port: 3 },
    ]);
    assert.equal(await readFile(full.outputFile, 'utf8'), '127.0.0.1:1\r\n127.0.0.1:3\r\n');
    const incremental = await (await fetch(`${base}/api/scans/${id}?after=1`)).json();
    assert.equal(incremental.matchesOffset, 1);
    assert.equal(incremental.verifiedCount, 2);
    assert.deepEqual(incremental.matches, [{ host: '127.0.0.1', port: 3 }]);

    const summary = await (await fetch(`${base}/api/scans/${id}?summary=1`)).json();
    assert.equal(summary.status, 'done');
    assert.equal(summary.total, 3);
    assert.equal(summary.scanned, 3);
    assert.equal(summary.verifiedCount, 2);
    assert.equal(summary.stats.verified, 2);
    assert.equal(summary.outputFile, full.outputFile);
    assert.equal(summary.outputError, null);
    assert.equal(Object.hasOwn(summary, 'matches'), false);
    assert.equal(Object.hasOwn(summary, 'matchesOffset'), false);
  } finally {
    await app.close();
    assert.ok(outputDirectory.startsWith(join(tmpdir(), 'rdp-check-test-')));
    await rm(outputDirectory, { recursive: true, force: true });
  }
});

test('does not create a final Desktop file after cancellation', async () => {
  const outputDirectory = await mkdtemp(join(tmpdir(), 'rdp-check-test-'));
  const app = await startServer({
    port: 0,
    openBrowser: false,
    outputDirectory,
    probe: (_host, _port, { signal }) => new Promise((resolve) => {
      signal.addEventListener('abort', () => resolve({ ok: false, reason: 'cancelled' }), { once: true });
    }),
  });
  const base = `http://127.0.0.1:${app.port}`;
  try {
    const response = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: '127.0.0.1:1', concurrency: 1, timeoutMs: 3000 }),
    });
    assert.equal(response.status, 201);
    const { id } = await response.json();
    const stopped = await fetch(`${base}/api/scans/${id}/cancel`, { method: 'POST' });
    assert.equal(stopped.status, 200);
    let snapshot;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      snapshot = await (await fetch(`${base}/api/scans/${id}`)).json();
      if (snapshot.status === 'cancelled') break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(snapshot.status, 'cancelled');
    assert.equal(snapshot.outputFile, null);
    assert.deepEqual(await readdir(outputDirectory), []);
  } finally {
    await app.close();
    assert.ok(outputDirectory.startsWith(join(tmpdir(), 'rdp-check-test-')));
    await rm(outputDirectory, { recursive: true, force: true });
  }
});
