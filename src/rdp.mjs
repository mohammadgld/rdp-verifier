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

export function parseCredsspChallenge(bytes) {
  if (!Buffer.isBuffer(bytes)) return false;
  if (bytes.length < 2) return null;
  if (bytes[0] !== 0x30) return false;
  if ((bytes[1] === 0x81 && bytes.length < 3) || (bytes[1] === 0x82 && bytes.length < 4)) return null;
  const outer = readDerElement(bytes, 0, bytes.length);
  if (!outer || outer.end > MAX_CREDSSP) return false;
  if (outer.end > bytes.length) return null;
  const version = readDerElement(bytes, outer.valueStart, outer.end);
  if (!version || version.tag !== 0xa0 || version.end > outer.end) return false;
  const negotiation = readDerElement(bytes, version.end, outer.end);
  if (!negotiation || negotiation.tag !== 0xa1 || negotiation.end > outer.end) return false;
  const signature = bytes.indexOf(NTLM_SIGNATURE, negotiation.valueStart);
  if (signature < negotiation.valueStart || signature + 48 > negotiation.end) return false;
  return bytes.readUInt32LE(signature + 8) === 2;
}

export function probeRdp(host, port, { timeoutMs = 3000, signal } = {}) {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve({ ok: false, reason: 'cancelled' });

    const socket = new net.Socket();
    let secured;
    let stage = 'confirm';
    let data = Buffer.alloc(0);
    let done = false;
    const finish = (ok, reason) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
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
        if (done || stage !== 'challenge') return;
        data = Buffer.concat([data, part]);
        if (data.length > MAX_CREDSSP) return finish(false, 'oversized-challenge');
        const outcome = parseCredsspChallenge(data);
        if (outcome === true) finish(true, 'credssp-challenge');
        else if (outcome === false) finish(false, 'invalid-challenge');
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
