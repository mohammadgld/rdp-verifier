import net from 'node:net';
import tls from 'node:tls';

// X.224 Connection Request with SSL, CredSSP and CredSSP + early auth offered.
const CONNECTION_REQUEST = Buffer.from('030000130ee00000000000010008000b000000', 'hex');

// CredSSP TSRequest carrying an NTLM Type 1 negotiate message, with no credentials.
const CREDSSP_NEGOTIATE = Buffer.from(
  '3037a003020106a130302e302ca02a0428' +
  '4e544c4d5353500001000000b78208e2' +
  '00000000000000000000000000000000' +
  '0a0063450000000f',
  'hex',
);

const NTLM_SIGNATURE = Buffer.from('NTLMSSP\0', 'ascii');
const MAX_TPKT = 512;
const MAX_CREDSSP = 16_384;
const CHALLENGE_OBSERVATION_MS = 300;

export function parseNegotiationConfirm(frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 19 || frame[0] !== 3 || frame[1] !== 0) return null;
  const frameLength = frame.readUInt16BE(2);
  if (frameLength !== frame.length || frameLength > MAX_TPKT) return null;
  if (frame[4] + 5 !== frameLength || frame[5] !== 0xd0) return null;
  if (frame[11] !== 2 || frame.readUInt16LE(13) !== 8) return null;
  const protocol = frame.readUInt32LE(15);
  if (protocol !== 2 && protocol !== 8) return null;
  return { protocol, flags: frame[12] };
}

function readDerElement(bytes, offset, limit) {
  if (offset + 2 > limit) return null;
  const tag = bytes[offset];
  const first = bytes[offset + 1];
  let length;
  let valueStart;
  if (first < 0x80) {
    length = first;
    valueStart = offset + 2;
  } else if (first === 0x81 && offset + 3 <= limit) {
    length = bytes[offset + 2];
    valueStart = offset + 3;
  } else if (first === 0x82 && offset + 4 <= limit) {
    length = bytes.readUInt16BE(offset + 2);
    valueStart = offset + 4;
  } else {
    return null;
  }
  if (length > MAX_CREDSSP) return null;
  return { tag, valueStart, end: valueStart + length };
}

function ntlmToken(bytes, depth = 0) {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(NTLM_SIGNATURE)) return bytes;
  if (depth >= 8 || bytes.length < 2) return null;
  const container = readDerElement(bytes, 0, bytes.length);
  if (!container || container.end !== bytes.length || !(container.tag & 0x20)) return null;
  let offset = container.valueStart;
  let found = null;
  let rejected = false;
  while (offset < container.end) {
    const child = readDerElement(bytes, offset, container.end);
    if (!child || child.end > container.end) return null;
    if (container.tag === 0x30 && child.tag === 0xa0) {
      const state = readDerElement(bytes, child.valueStart, child.end);
      if (state?.tag === 0x0a && state.end === child.end) {
        if (state.end - state.valueStart !== 1) return null;
        rejected ||= bytes[state.valueStart] === 2; // SPNEGO negState=reject.
      }
    }
    if (child.tag === 0x04 || (child.tag & 0x20)) {
      const nested = child.tag === 0x04
        ? bytes.subarray(child.valueStart, child.end)
        : bytes.subarray(offset, child.end);
      const candidate = ntlmToken(nested, depth + 1);
      if (candidate) {
        if (found) return null;
        found = candidate;
      }
    }
    offset = child.end;
  }
  return rejected ? null : found;
}

function securityBuffer(bytes, offset, minimumPayloadOffset) {
  if (offset + 8 > bytes.length) return null;
  const length = bytes.readUInt16LE(offset);
  const maximum = bytes.readUInt16LE(offset + 2);
  const position = bytes.readUInt32LE(offset + 4);
  if (length > maximum) return null;
  if (length === 0) return { start: 0, end: 0, length: 0 };
  if (position < minimumPayloadOffset || position + length > bytes.length) return null;
  return { start: position, end: position + length, length };
}

function validTargetInfo(bytes) {
  if (!bytes.length) return true;
  let offset = 0;
  while (offset + 4 <= bytes.length) {
    const id = bytes.readUInt16LE(offset);
    const length = bytes.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + length > bytes.length) return false;
    if (id === 0) return length === 0 && offset === bytes.length;
    offset += length;
  }
  return false;
}

function validNtlmChallenge(bytes) {
  if (!bytes || bytes.length < 48 || !bytes.subarray(0, 8).equals(NTLM_SIGNATURE)) return false;
  if (bytes.readUInt32LE(8) !== 2) return false;
  const flags = bytes.readUInt32LE(20);
  if (!(flags & 0x00000200) || !(flags & 0x00000003)) return false;
  if ((flags & 0x02000000) && bytes.length < 56) return false;
  if (bytes.subarray(24, 32).every((byte) => byte === 0)) return false;
  if (bytes.subarray(32, 40).some((byte) => byte !== 0)) return false;
  const minimumPayloadOffset = flags & 0x02000000 ? 56 : 48;
  const targetName = securityBuffer(bytes, 12, minimumPayloadOffset);
  const targetInfo = securityBuffer(bytes, 40, minimumPayloadOffset);
  if (!targetName || !targetInfo) return false;
  if ((flags & 0x00000001) && targetName.length % 2 !== 0) return false;
  if (targetInfo.length && !(flags & 0x00800000)) return false;
  return validTargetInfo(bytes.subarray(targetInfo.start, targetInfo.end));
}

function validNegoData(bytes, field) {
  const sequence = readDerElement(bytes, field.valueStart, field.end);
  if (!sequence || sequence.tag !== 0x30 || sequence.end !== field.end) return false;
  let offset = sequence.valueStart;
  let foundChallenge = false;
  while (offset < sequence.end) {
    const item = readDerElement(bytes, offset, sequence.end);
    if (!item || item.tag !== 0x30 || item.end > sequence.end) return false;
    const tokenField = readDerElement(bytes, item.valueStart, item.end);
    if (!tokenField || tokenField.tag !== 0xa0 || tokenField.end !== item.end) return false;
    const octet = readDerElement(bytes, tokenField.valueStart, tokenField.end);
    if (!octet || octet.tag !== 0x04 || octet.end !== tokenField.end) return false;
    if (!validNtlmChallenge(ntlmToken(bytes.subarray(octet.valueStart, octet.end)))) return false;
    foundChallenge = true;
    offset = item.end;
  }
  return foundChallenge;
}

function validTsRequest(bytes, outer) {
  const versionField = readDerElement(bytes, outer.valueStart, outer.end);
  if (!versionField || versionField.tag !== 0xa0 || versionField.end > outer.end) return false;
  const version = readDerElement(bytes, versionField.valueStart, versionField.end);
  if (!version || version.tag !== 0x02 || version.end !== versionField.end) return false;
  const versionLength = version.end - version.valueStart;
  if (versionLength < 1 || versionLength > 4 || (bytes[version.valueStart] & 0x80)) return false;
  let versionNumber = 0;
  for (let offset = version.valueStart; offset < version.end; offset += 1) {
    versionNumber = versionNumber * 256 + bytes[offset];
  }
  if (versionNumber < 2) return false;

  let offset = versionField.end;
  let hasChallenge = false;
  while (offset < outer.end) {
    const field = readDerElement(bytes, offset, outer.end);
    if (!field || field.end > outer.end) return false;
    if (field.tag === 0xa4) return false; // An errorCode requires an RDP client to fail.
    if (field.tag !== 0xa1 || hasChallenge || !validNegoData(bytes, field)) return false;
    hasChallenge = true;
    offset = field.end;
  }
  return hasChallenge;
}

export function parseCredsspChallenge(bytes) {
  if (!Buffer.isBuffer(bytes)) return false;
  if (bytes.length === 0) return null;
  let offset = 0;
  let hasChallenge = false;
  while (offset < bytes.length) {
    if (bytes[offset] !== 0x30) return false;
    if (offset + 2 > bytes.length) return null;
    if ((bytes[offset + 1] === 0x81 && offset + 3 > bytes.length)
      || (bytes[offset + 1] === 0x82 && offset + 4 > bytes.length)) return null;
    const outer = readDerElement(bytes, offset, bytes.length);
    if (!outer || outer.end - offset > MAX_CREDSSP) return false;
    if (outer.end > bytes.length) return null;
    if (!validTsRequest(bytes, outer)) return false;
    hasChallenge = true;
    offset = outer.end;
  }
  return hasChallenge;
}

export function probeRdp(host, port, { timeoutMs = 3000, signal } = {}) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve({ ok: false, reason: 'cancelled' });

    const socket = new net.Socket();
    let secured;
    let stage = 'confirm';
    let data = Buffer.alloc(0);
    let done = false;
    let observationTimer;
    const finish = (ok, reason) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(observationTimer);
      signal?.removeEventListener('abort', onAbort);
      secured?.destroy();
      socket.destroy();
      resolve({ ok, reason });
    };
    const onAbort = () => finish(false, 'cancelled');
    const timer = setTimeout(() => finish(false, 'timeout'), timeoutMs);

    const onRawData = (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length < 4) return;
      if (data[0] !== 3 || data[1] !== 0) return finish(false, 'not-rdp');
      const expected = data.readUInt16BE(2);
      if (expected < 11 || expected > MAX_TPKT || data.length > MAX_TPKT) return finish(false, 'invalid-rdp');
      if (data.length < expected) return;
      const confirm = parseNegotiationConfirm(data.subarray(0, expected));
      if (!confirm) return finish(false, 'no-credssp');

      stage = 'tls';
      data = Buffer.alloc(0);
      socket.removeListener('data', onRawData);
      secured = tls.connect({ socket, rejectUnauthorized: false });
      secured.once('secureConnect', () => {
        if (done) return;
        stage = 'challenge';
        secured.write(CREDSSP_NEGOTIATE);
      });
      secured.on('data', (part) => {
        if (done || (stage !== 'challenge' && stage !== 'observing')) return;
        data = Buffer.concat([data, part]);
        if (data.length > MAX_CREDSSP) return finish(false, 'oversized-challenge');
        const outcome = parseCredsspChallenge(data);
        if (outcome === false) return finish(false, 'invalid-challenge');
        if (outcome === true && stage === 'challenge') {
          stage = 'observing';
          observationTimer = setTimeout(() => {
            if (parseCredsspChallenge(data) === true) finish(true, 'credssp-challenge');
            else finish(false, 'invalid-challenge');
          }, CHALLENGE_OBSERVATION_MS);
        }
      });
      secured.on('error', () => finish(false, 'tls-error'));
      secured.on('close', () => finish(false, 'closed'));
    };

    socket.on('data', onRawData);
    socket.on('error', () => finish(false, stage === 'confirm' ? 'connect-error' : 'closed'));
    socket.on('close', () => finish(false, 'closed'));
    socket.once('connect', () => socket.write(CONNECTION_REQUEST));
    signal?.addEventListener('abort', onAbort, { once: true });
    socket.connect(port, host);
  });
}
