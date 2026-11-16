import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseTargets } from './src/targets.mjs';
import { createScan } from './src/scan.mjs';

const assets = new Map([
  ['/', { file: new URL('./public/index.html', import.meta.url), type: 'text/html; charset=utf-8' }],
  ['/app.css', { file: new URL('./public/app.css', import.meta.url), type: 'text/css; charset=utf-8' }],
  ['/app.js', { file: new URL('./public/app.js', import.meta.url), type: 'text/javascript; charset=utf-8' }],
]);

function respondJson(response, status, body) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new Error('Invalid request format.');
  }
}

function snapshot({ id, scan, output }, after = 0, summaryOnly = false) {
  const summary = {
    id,
    status: scan.status === 'done' && output.state !== 'finished' ? 'saving' : scan.status,
    total: scan.total,
    scanned: scan.scanned,
    verifiedCount: scan.matches.length,
    stats: scan.stats,
    outputFile: output.file,
    outputError: output.error,
  };
  if (summaryOnly) return summary;
  const matchesOffset = Math.min(after, scan.matches.length);
  return { ...summary, matches: scan.matches.slice(matchesOffset), matchesOffset };
}

export async function startServer({ port = 8765, openBrowser = false, outputDirectory = join(homedir(), 'Desktop'), probe } = {}) {
  let active = null;
  const server = http.createServer(async (request, response) => {
    const actualPort = server.address().port;
    const allowedHosts = [`127.0.0.1:${actualPort}`, `localhost:${actualPort}`];
    if (!allowedHosts.includes(request.headers.host)) {
      return respondJson(response, 403, { error: 'Access denied.' });
    }
    const origin = request.headers.origin;
    if (origin && !allowedHosts.some((host) => origin === `http://${host}`)) {
      return respondJson(response, 403, { error: 'Requests from another origin are not accepted.' });
    }

    const requestUrl = new URL(request.url, `http://${request.headers.host}`);
    const pathname = requestUrl.pathname;
    const asset = assets.get(pathname);
    if (request.method === 'GET' && asset) {
      try {
        const bytes = await readFile(asset.file);
        response.writeHead(200, { 'Content-Type': asset.type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
        return response.end(bytes);
      } catch {
        return respondJson(response, 500, { error: 'Application file could not be read.' });
      }
    }

    if (request.method === 'POST' && pathname === '/api/scans') {
      if (active && (active.scan.status === 'running' || active.scan.status === 'cancelling'
        || (active.scan.status === 'done' && active.output.state !== 'finished'))) {
        return respondJson(response, 409, { error: 'Another scan is already running.' });
      }
      if (!request.headers['content-type']?.startsWith('application/json')) {
        return respondJson(response, 415, { error: 'Request must use JSON.' });
      }
      try {
        const body = await readJson(request);
        const targets = parseTargets(body.input);
        const scan = createScan(targets, { concurrency: body.concurrency, timeoutMs: body.timeoutMs, probe });
        const id = randomUUID();
        const record = { id, scan, output: { state: 'pending', file: null, error: null } };
        active = record;
        void scan.done.then(async () => {
          if (scan.status !== 'done') return;
          record.output.state = 'saving';
          const filename = `rdp-results-${new Date().toISOString().replace(/[:.]/g, '-')}-${id.slice(0, 8)}.txt`;
          try {
            const outputFile = join(outputDirectory, filename);
            const contents = scan.matches.length
              ? `${scan.matches.map(({ host, port }) => `${host}:${port}`).join('\r\n')}\r\n`
              : '';
            await writeFile(outputFile, contents, { encoding: 'utf8', flag: 'wx' });
            record.output.file = outputFile;
          } catch (error) {
            record.output.error = `Could not save the Desktop result file: ${error.message}`;
          } finally {
            record.output.state = 'finished';
          }
        });
        return respondJson(response, 201, { id, total: targets.length });
      } catch (error) {
        return respondJson(response, 400, { error: error.message || 'Invalid request.' });
      }
    }

    const route = /^\/api\/scans\/([a-f0-9-]+)(\/cancel)?$/.exec(pathname);
    if (route && active?.id === route[1]) {
      if (request.method === 'GET' && !route[2]) {
        const rawAfter = requestUrl.searchParams.get('after');
        const after = rawAfter === null ? 0 : Number(rawAfter);
        if (rawAfter !== null && (!/^\d+$/.test(rawAfter) || !Number.isSafeInteger(after))) {
          return respondJson(response, 400, { error: 'Invalid result cursor.' });
        }
        return respondJson(response, 200, snapshot(active, after, requestUrl.searchParams.get('summary') === '1'));
      }
      if (request.method === 'POST' && route[2]) {
        active.scan.cancel();
        return respondJson(response, 200, { status: active.scan.status });
      }
    }
    return respondJson(response, 404, { error: 'Not found.' });
  });

  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen);
    server.listen(port, '127.0.0.1', resolveListen);
  });
  const actualPort = server.address().port;
  const url = `http://127.0.0.1:${actualPort}`;
  if (openBrowser && process.platform === 'win32') {
    const child = spawn('cmd.exe', ['/d', '/s', '/c', `start "" "${url}"`], {
      detached: true,
      stdio: 'ignore',
      windowsHide: true,
    });
    child.unref();
  }
  return {
    port: actualPort,
    url,
    close: async () => {
      active?.scan.cancel();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  startServer({ port: 8765, openBrowser: true })
    .then(({ url }) => console.log(`RDP Verifier: ${url}\nPress Ctrl+C to exit.`))
    .catch((error) => {
      console.error(`Application could not start: ${error.message}`);
      process.exitCode = 1;
    });
}
