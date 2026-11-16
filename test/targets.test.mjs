import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTargets } from '../src/targets.mjs';

test('parses individual IPv4 targets with explicit or default ports', () => {
  assert.deepEqual(parseTargets('192.168.1.10:3390\n10.0.0.1'), [
    { host: '192.168.1.10', port: 3390 },
    { host: '10.0.0.1', port: 3389 },
  ]);
});

test('expands CIDR and explicit address ranges inclusively', () => {
  assert.deepEqual(parseTargets('10.0.0.2/31:3391\n10.0.0.7-10.0.0.8:3389'), [
    { host: '10.0.0.2', port: 3391 },
    { host: '10.0.0.3', port: 3391 },
    { host: '10.0.0.7', port: 3389 },
    { host: '10.0.0.8', port: 3389 },
  ]);
});

test('accepts CSV data, a header, comments, BOM and CRLF', () => {
  assert.deepEqual(parseTargets('\ufeffip,port\r\n# note\r\n192.0.2.1,3392 # office\r\n\r\n192.0.2.2,3389'), [
    { host: '192.0.2.1', port: 3392 },
    { host: '192.0.2.2', port: 3389 },
  ]);
});

test('deduplicates identical host and port but preserves different ports', () => {
  assert.deepEqual(parseTargets('192.0.2.1:3389\n192.0.2.0/31:3389\n192.0.2.1:3390'), [
    { host: '192.0.2.1', port: 3389 },
    { host: '192.0.2.0', port: 3389 },
    { host: '192.0.2.1', port: 3390 },
  ]);
});

test('rejects malformed addresses, ranges, prefixes and ports with line numbers', () => {
  const badInputs = [
    '300.1.1.1:3389',
    '01.2.3.4:3389',
    '192.0.2.1:0',
    '192.0.2.1:65536',
    '192.0.2.0/33:3389',
    '192.0.2.9-192.0.2.1:3389',
    'example.com:3389',
    '192.0.2.1:abc',
  ];
  for (const input of badInputs) {
    assert.throws(() => parseTargets(`192.0.2.1\n${input}`), /2/);
  }
});

test('rejects empty input and ranges larger than the configured cap', () => {
  assert.throws(() => parseTargets(' \n# only comment'), /empty/);
  assert.throws(() => parseTargets('0.0.0.0/0'), /exceeds/);
  assert.throws(() => parseTargets('192.0.2.0/30', { maxTargets: 3 }), /exceeds/);
});

test('accepts a file with more than 196,000 unique targets', () => {
  const input = Array.from({ length: 200_000 }, (_, index) =>
    `10.${Math.floor(index / 65_536)}.${Math.floor(index / 256) % 256}.${index % 256}:3389`,
  ).join('\r\n');
  const targets = parseTargets(input);
  assert.equal(targets.length, 200_000);
  assert.deepEqual(targets.at(-1), { host: '10.3.13.63', port: 3389 });
});
