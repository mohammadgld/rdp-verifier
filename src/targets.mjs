const DEFAULT_PORT = 3389;
const DEFAULT_MAX_TARGETS = 1_000_000;

function ipv4ToNumber(value, lineNumber) {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part))) {
    throw new Error(`Line ${lineNumber}: invalid IPv4 address.`);
  }
  const octets = parts.map(Number);
  if (octets.some((octet) => octet > 255)) {
    throw new Error(`Line ${lineNumber}: invalid IPv4 address.`);
  }
  return octets.reduce((number, octet) => number * 256 + octet, 0);
}

function numberToIpv4(number) {
  const first = Math.floor(number / 16_777_216);
  const second = Math.floor(number / 65_536) % 256;
  const third = Math.floor(number / 256) % 256;
  const fourth = number % 256;
  return `${first}.${second}.${third}.${fourth}`;
}

function parseAddressRange(value, lineNumber) {
  if (value.includes('/')) {
    const cidr = /^([^/]+)\/(\d{1,2})$/.exec(value);
    if (!cidr || Number(cidr[2]) > 32) {
      throw new Error(`Line ${lineNumber}: invalid CIDR prefix.`);
    }
    const address = ipv4ToNumber(cidr[1].trim(), lineNumber);
    const size = 2 ** (32 - Number(cidr[2]));
    const start = Math.floor(address / size) * size;
    return [start, start + size - 1];
  }

  if (value.includes('-')) {
    const range = /^(.+?)\s*-\s*(.+)$/.exec(value);
    if (!range) {
      throw new Error(`Line ${lineNumber}: invalid IP range.`);
    }
    const start = ipv4ToNumber(range[1].trim(), lineNumber);
    const end = ipv4ToNumber(range[2].trim(), lineNumber);
    if (end < start) {
      throw new Error(`Line ${lineNumber}: the range ends before it starts.`);
    }
    return [start, end];
  }

  const address = ipv4ToNumber(value, lineNumber);
  return [address, address];
}

function parseLine(line, lineNumber) {
  const separator = line.includes(',') ? ',' : ':';
  const parts = line.split(separator);
  if (parts.length > 2) {
    throw new Error(`Line ${lineNumber}: invalid input format.`);
  }
  const address = parts[0].trim();
  const portText = parts.length === 2 ? parts[1].trim() : null;
  if (!address) {
    throw new Error(`Line ${lineNumber}: IP address is missing.`);
  }
  if (portText !== null && !/^\d+$/.test(portText)) {
    throw new Error(`Line ${lineNumber}: invalid port.`);
  }
  const port = portText === null ? DEFAULT_PORT : Number(portText);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Line ${lineNumber}: port must be between 1 and 65535.`);
  }
  const [start, end] = parseAddressRange(address, lineNumber);
  return { start, end, port };
}

export function parseTargets(input, { maxTargets = DEFAULT_MAX_TARGETS } = {}) {
  if (typeof input !== 'string') {
    throw new TypeError('Input list must be text.');
  }
  if (!Number.isSafeInteger(maxTargets) || maxTargets < 1) {
    throw new RangeError('Invalid maximum target count.');
  }

  const targets = [];
  const seen = new Set();
  const lines = input.replace(/^\uFEFF/, '').split(/\r?\n/);

  for (const [index, rawLine] of lines.entries()) {
    const lineNumber = index + 1;
    const line = rawLine.split('#', 1)[0].trim();
    if (!line || /^(?:ip|host|range)\s*,\s*port$/i.test(line)) {
      continue;
    }
    const { start, end, port } = parseLine(line, lineNumber);
    if (end - start + 1 > maxTargets) {
      throw new Error(`Line ${lineNumber}: range exceeds the ${maxTargets} target limit.`);
    }
    for (let address = start; address <= end; address += 1) {
      const key = `${address}:${port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (seen.size > maxTargets) {
        throw new Error(`Target count exceeds the ${maxTargets} limit.`);
      }
      targets.push({ host: numberToIpv4(address), port });
    }
  }

  if (targets.length === 0) {
    throw new Error('Input list is empty.');
  }
  return targets;
}
