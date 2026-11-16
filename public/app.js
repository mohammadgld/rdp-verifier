const $ = (id) => document.getElementById(id);
const els = {
  fileInput: $('fileInput'),
  fileName: $('fileName'),
  fileButton: document.querySelector('.file-button'),
  concurrency: $('concurrency'),
  start: $('startButton'),
  cancel: $('cancelButton'),
  message: $('message'),
  matchCount: $('matchCount'),
  progressArea: $('progressArea'),
  scanStatus: $('scanStatus'),
  progressNumbers: $('progressNumbers'),
  progressPercent: $('progressPercent'),
  progressTrack: $('progressTrack'),
  progressFill: $('progressFill'),
};

const numberFmt = new Intl.NumberFormat('en-US');
const percentFmt = new Intl.NumberFormat('en-US', {
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
});
let loadedText = '';
let scanId = null;
let pollTimer = null;
let pollInFlight = false;
let pollErrors = 0;
let cancelWhenReady = false;

function setMessage(message, isError = false) {
  els.message.textContent = message;
  els.message.classList.toggle('is-error', isError);
}

function setRunning(running) {
  els.fileInput.disabled = running;
  els.concurrency.disabled = running;
  els.start.disabled = running;
  els.cancel.hidden = !running;
  els.cancel.disabled = false;
  els.fileButton.classList.toggle('is-disabled', running);
}

function clearSelectedFile() {
  loadedText = '';
  scanId = null;
  cancelWhenReady = false;
  clearTimeout(pollTimer);
  els.fileName.textContent = 'No file selected';
  els.fileButton.classList.remove('has-file');
  els.matchCount.textContent = '0 found';
  els.progressArea.hidden = true;
  els.progressArea.classList.remove('is-working');
  setMessage('');
}

function schedulePoll() {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(poll, 500);
}

function renderSnapshot(snapshot) {
  const total = Math.max(0, Number(snapshot.total) || 0);
  const scanned = Math.min(Math.max(0, Number(snapshot.scanned) || 0), total);
  const verified = Math.max(0, Number(snapshot.verifiedCount ?? snapshot.stats?.verified) || 0);
  const rounded = total ? Math.round((scanned / total) * 1000) / 10 : 0;
  const percentage = scanned < total ? Math.min(rounded, 99.9) : rounded;

  els.matchCount.textContent = `${numberFmt.format(verified)} found`;
  els.progressArea.hidden = false;
  els.progressNumbers.textContent = `${numberFmt.format(scanned)} / ${numberFmt.format(total)}`;
  els.progressPercent.textContent = `${percentFmt.format(percentage)}%`;
  els.progressFill.style.width = `${percentage}%`;
  els.progressTrack.setAttribute('aria-valuenow', String(percentage));
  els.progressTrack.setAttribute('aria-valuetext',
    `${percentFmt.format(percentage)} percent, ${numberFmt.format(scanned)} of ${numberFmt.format(total)} targets`);
  const working = ['running', 'cancelling', 'saving'].includes(snapshot.status);
  els.progressArea.classList.toggle('is-working', working);
  els.progressArea.setAttribute('aria-busy', String(working));

  if (snapshot.status === 'running') {
    els.scanStatus.textContent = 'Scanning…';
    schedulePoll();
  } else if (snapshot.status === 'cancelling') {
    els.scanStatus.textContent = 'Stopping…';
    els.cancel.disabled = true;
    schedulePoll();
  } else if (snapshot.status === 'saving') {
    els.scanStatus.textContent = 'Saving…';
    els.cancel.hidden = true;
    setMessage('Saving results to Desktop…');
    schedulePoll();
  } else if (snapshot.status === 'done' || snapshot.status === 'completed') {
    els.scanStatus.textContent = 'Scan complete';
    setRunning(false);
    if (snapshot.outputError) setMessage(snapshot.outputError, true);
    else setMessage(snapshot.outputFile ? 'Saved to Desktop.' : 'Scan complete.');
  } else if (snapshot.status === 'cancelled') {
    els.scanStatus.textContent = 'Scan stopped';
    setRunning(false);
    setMessage('Stopped. No final file saved.');
  } else if (snapshot.status === 'error' || snapshot.status === 'failed') {
    els.scanStatus.textContent = 'Error';
    setRunning(false);
    setMessage(snapshot.error || 'The scan failed.', true);
  } else {
    schedulePoll();
  }
}

async function poll() {
  if (!scanId || pollInFlight) return;
  const requestedId = scanId;
  pollInFlight = true;
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(requestedId)}?summary=1`, { cache: 'no-store' });
    const data = await response.json();
    if (scanId !== requestedId) return;
    if (!response.ok) throw new Error(data.error || 'Could not read scan status.');
    pollErrors = 0;
    renderSnapshot(data);
  } catch (error) {
    if (scanId !== requestedId) return;
    pollErrors += 1;
    if (pollErrors < 4) {
      setMessage('Reconnecting…', true);
      schedulePoll();
    } else {
      clearTimeout(pollTimer);
      setRunning(false);
      els.progressArea.classList.remove('is-working');
      els.scanStatus.textContent = 'Disconnected';
      setMessage(error.message || 'Connection to the scan engine was lost.', true);
    }
  } finally {
    pollInFlight = false;
    if (scanId && scanId !== requestedId) schedulePoll();
  }
}

async function startScan() {
  if (els.start.disabled) return;
  const input = loadedText;
  const concurrency = Number(els.concurrency.value);
  if (!input) return setMessage('Choose a file first.', true);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 3000) {
    return setMessage('Concurrent checks must be between 1 and 3000.', true);
  }

  clearTimeout(pollTimer);
  scanId = null;
  cancelWhenReady = false;
  pollErrors = 0;
  els.matchCount.textContent = '0 found';
  els.progressArea.hidden = false;
  els.progressArea.classList.add('is-working');
  els.progressArea.setAttribute('aria-busy', 'true');
  els.scanStatus.textContent = 'Preparing…';
  els.progressNumbers.textContent = '0 / 0';
  els.progressPercent.textContent = '0.0%';
  els.progressFill.style.width = '0%';
  els.progressTrack.setAttribute('aria-valuenow', '0');
  els.progressTrack.setAttribute('aria-valuetext', '0.0 percent');
  setRunning(true);
  setMessage('');
  try {
    const response = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, concurrency, timeoutMs: 3000 }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Could not start the scan.');
    scanId = data.id;
    if (cancelWhenReady) await cancelScan();
    else await poll();
  } catch (error) {
    setRunning(false);
    els.progressArea.hidden = true;
    setMessage(error.message || 'Could not start the scan.', true);
  }
}

async function cancelScan() {
  els.cancel.disabled = true;
  if (!scanId) {
    cancelWhenReady = true;
    setMessage('Stopping…');
    return;
  }
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(scanId)}/cancel`, { method: 'POST' });
    if (!response.ok) throw new Error('Could not stop the scan.');
    await poll();
  } catch (error) {
    els.cancel.disabled = false;
    setMessage(error.message || 'Could not stop the scan.', true);
  }
}

async function importFile() {
  const file = els.fileInput.files?.[0];
  if (!file) return;
  clearSelectedFile();
  els.fileName.textContent = `Loading ${file.name}…`;
  setMessage('Loading file…');
  try {
    await new Promise((resolve) => requestAnimationFrame(resolve));
    const content = (await file.text()).replace(/^\uFEFF/, '').trim();
    if (!content) throw new Error('The file is empty.');
    loadedText = content;
    els.fileName.textContent = file.name;
    els.fileButton.classList.add('has-file');
    setMessage('');
  } catch (error) {
    els.fileName.textContent = 'No file selected';
    setMessage(error.message || 'Could not read the file.', true);
  } finally {
    els.fileInput.value = '';
  }
}

els.start.addEventListener('click', startScan);
els.cancel.addEventListener('click', cancelScan);
els.fileInput.addEventListener('change', importFile);
els.fileButton.addEventListener('keydown', (event) => {
  if ((event.key === 'Enter' || event.key === ' ') && !els.fileInput.disabled) {
    event.preventDefault();
    els.fileInput.click();
  }
});
