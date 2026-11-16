import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import tls from 'node:tls';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseNegotiationConfirm, parseCredsspChallenge, probeRdp } from '../src/rdp.mjs';

const fixture = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const NLA_CONFIRM = Buffer.from('030000130ed000001234000200080002000000', 'hex');
const TLS_CONFIRM = Buffer.from('030000130ed000001234000200080001000000', 'hex');
const FAILED_CONFIRM = Buffer.from('030000130ed000001234000300080005000000', 'hex');

function der(tag, content) {
  const length = content.length < 128
    ? Buffer.from([content.length])
    : Buffer.from([0x81, content.length]);
  return Buffer.concat([Buffer.from([tag]), length, content]);
}

function challenge({ errorCode = false, badTargetInfoOffset = false, badTokenTail = false, spnegoState, shortVersion = false } = {}) {
  const ntlm = Buffer.alloc(shortVersion ? 48 : 60);
  ntlm.write('NTLMSSP\0', 0, 'ascii');
  ntlm.writeUInt32LE(2, 8);
  ntlm.writeUInt32LE(shortVersion ? 0x02000201 : 0x00800201, 20); // Unicode, NTLM, target information or version.
  Buffer.from('0102030405060708', 'hex').copy(ntlm, 24);
  if (!shortVersion) {
    ntlm.writeUInt16LE(4, 40);
    ntlm.writeUInt16LE(4, 42);
    ntlm.writeUInt32LE(badTargetInfoOffset ? 1000 : 56, 44);
  }
  // The target information payload is a terminating MsvAvEOL pair.
  const tokenBytes = spnegoState !== undefined
    ? der(0xa1, der(0x30, Buffer.concat([
      der(0xa0, der(0x0a, Buffer.from([spnegoState]))),
      der(0xa2, der(0x04, ntlm)),
    ])))
    : badTokenTail
      ? der(0x30, Buffer.concat([der(0x04, ntlm), Buffer.from([0xff])]))
      : ntlm;
  const token = der(0xa0, der(0x04, tokenBytes));
  const nego = der(0xa1, der(0x30, der(0x30, token)));
  const fields = [der(0xa0, der(0x02, Buffer.from([6]))), nego];
  if (errorCode) fields.push(der(0xa4, der(0x02, Buffer.from([5]))));
  return der(0x30, Buffer.concat(fields));
}

function errorResponse() {
  return der(0x30, Buffer.concat([
    der(0xa0, der(0x02, Buffer.from([6]))),
    der(0xa4, der(0x02, Buffer.from([5]))),
  ]));
}

async function localServer(onRequest) {
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.once('data', () => onRequest(socket));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

test('negotiation parser accepts only a complete CredSSP confirm', () => {
  assert.deepEqual(parseNegotiationConfirm(NLA_CONFIRM), { protocol: 2, flags: 0 });
  assert.equal(parseNegotiationConfirm(NLA_CONFIRM.subarray(0, 18)), null);
  assert.equal(parseNegotiationConfirm(TLS_CONFIRM), null);
  assert.equal(parseNegotiationConfirm(FAILED_CONFIRM), null);
  assert.equal(parseNegotiationConfirm(Buffer.from('HTTP/1.1 200 OK')), null);
});

test('challenge parser requires a full CredSSP NTLM challenge', () => {
  const message = challenge();
  assert.equal(parseCredsspChallenge(message), true);
  assert.equal(parseCredsspChallenge(message.subarray(0, 1)), null);
  assert.equal(parseCredsspChallenge(message.subarray(0, message.length - 1)), null);
  const falseMessage = Buffer.from(message);
  falseMessage.writeUInt32LE(1, falseMessage.indexOf('NTLMSSP') + 8);
  assert.equal(parseCredsspChallenge(falseMessage), false);
});

test('challenge parser rejects a CredSSP errorCode even alongside a Type 2 token', () => {
  assert.equal(parseCredsspChallenge(challenge({ errorCode: true })), false);
  assert.equal(parseCredsspChallenge(Buffer.concat([challenge(), errorResponse()])), false);
});

test('challenge parser rejects malformed NTLM security buffer offsets', () => {
  assert.equal(parseCredsspChallenge(challenge({ badTargetInfoOffset: true })), false);
});

test('challenge parser rejects a malformed SPNEGO token after a Type 2 payload', () => {
  assert.equal(parseCredsspChallenge(challenge({ badTokenTail: true })), false);
});

test('challenge parser rejects SPNEGO negState reject despite a valid Type 2 responseToken', () => {
  assert.equal(parseCredsspChallenge(challenge({ spnegoState: 2 })), false);
  assert.equal(parseCredsspChallenge(challenge({ spnegoState: 1 })), true);
});

test('challenge parser rejects a truncated NTLM Version field when NEGOTIATE_VERSION is set', () => {
  assert.equal(parseCredsspChallenge(challenge({ shortVersion: true })), false);
});

test('probe rejects a server that closes immediately after its challenge', async () => {
  const secureContext = tls.createSecureContext({
    key: await readFile(fixture('key.pem')),
    cert: await readFile(fixture('cert.pem')),
  });
  const server = await localServer((socket) => {
    socket.write(NLA_CONFIRM, () => {
      const secured = new tls.TLSSocket(socket, { isServer: true, secureContext });
      secured.once('data', () => {
        secured.write(challenge(), () => setTimeout(() => secured.end(), 20));
      });
      secured.on('error', () => {});
    });
  });
  try {
    const result = await probeRdp('127.0.0.1', server.port, { timeoutMs: 1000 });
    assert.equal(result.ok, false);
  } finally {
    await server.close();
  }
});

test('probe rejects a server error sent right after a challenge', async () => {
  const secureContext = tls.createSecureContext({
    key: await readFile(fixture('key.pem')),
    cert: await readFile(fixture('cert.pem')),
  });
  const server = await localServer((socket) => {
    socket.write(NLA_CONFIRM, () => {
      const secured = new tls.TLSSocket(socket, { isServer: true, secureContext });
      secured.once('data', () => {
        secured.write(challenge(), () => setTimeout(() => secured.write(errorResponse()), 20));
      });
      secured.on('error', () => {});
    });
  });
  try {
    const result = await probeRdp('127.0.0.1', server.port, { timeoutMs: 1000 });
    assert.equal(result.ok, false);
  } finally {
    await server.close();
  }
});

test('probe keeps a real RDP/CredSSP challenge and handles fragmented replies', async () => {
  const secureContext = tls.createSecureContext({
    key: await readFile(fixture('key.pem')),
    cert: await readFile(fixture('cert.pem')),
  });
  const server = await localServer((socket) => {
    socket.write(NLA_CONFIRM.subarray(0, 3));
    setTimeout(() => socket.write(NLA_CONFIRM.subarray(3), () => {
      const secured = new tls.TLSSocket(socket, { isServer: true, secureContext });
      secured.on('data', () => {
        const response = challenge();
        secured.write(response.subarray(0, 1));
        setTimeout(() => secured.write(response.subarray(1)), 10);
      });
      secured.on('error', () => {});
    }), 10);
  });
  try {
    const result = await probeRdp('127.0.0.1', server.port, { timeoutMs: 3000 });
    assert.equal(result.ok, true);
  } finally {
    await server.close();
  }
});

test('probe rejects open non-RDP ports, partial packets and stalled services', async () => {
  for (const action of [
    (socket) => socket.write('HTTP/1.1 200 OK\r\n'),
    (socket) => socket.write(NLA_CONFIRM.subarray(0, 8)),
    () => {},
  ]) {
    const server = await localServer(action);
    try {
      const result = await probeRdp('127.0.0.1', server.port, { timeoutMs: 150 });
      assert.equal(result.ok, false);
    } finally {
      await server.close();
    }
  }
});

test('probe rejects RDP negotiation without a working authentication exchange', async () => {
  const server = await localServer((socket) => socket.write(TLS_CONFIRM));
  try {
    const result = await probeRdp('127.0.0.1', server.port, { timeoutMs: 150 });
    assert.equal(result.ok, false);
  } finally {
    await server.close();
  }
});
