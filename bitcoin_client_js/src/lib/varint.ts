function bigintToSmallEndian(
  value: bigint,
  length: number,
  buffer: Buffer,
  offset: number
): void {
  for (let i = 0; i < length; i++) {
    if (buffer[i + offset] == undefined) {
      throw Error('Buffer too small');
    }
    buffer[i + offset] = Number(value % BigInt(256));
    value = value >> BigInt(8);
  }
}

function smallEndianToBigint(
  buffer: Buffer,
  offset: number,
  length: number
): bigint {
  let result = BigInt(0);
  for (let i = 0; i < length; i++) {
    if (buffer[i + offset] == undefined) {
      throw Error('Buffer too small');
    }
    result += BigInt(buffer[i + offset]) << BigInt(i * 8);
  }
  return result;
}

function getVarintSize(value: number | bigint): 1 | 3 | 5 | 9 {
  if (typeof value == 'number') {
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new Error(
        "createVarint with a 'number' input only support inputs not bigger than MAX_SAFE_INTEGER"
      );
    }
    value = BigInt(value);
  }

  if (value < BigInt(0)) {
    throw new Error('Negative numbers are not supported');
  }

  if (value >= BigInt(1) << BigInt(64)) {
    throw new Error('Too large for a Bitcoin-style varint');
  }

  if (value < BigInt(0xfd)) return 1;
  else if (value <= BigInt(0xffff)) return 3;
  else if (value <= BigInt(0xffffffff)) return 5;
  else return 9;
}

export function parseVarint(
  data: Buffer,
  offset: number
): readonly [bigint, number] {
  if (data[offset] == undefined) {
    throw Error('Buffer too small');
  }

  if (data[offset] < 0xfd) {
    return [BigInt(data[offset]), 1];
  } else {
    let size: number;
    if (data[offset] === 0xfd) size = 2;
    else if (data[offset] === 0xfe) size = 4;
    else size = 8;

    return [smallEndianToBigint(data, offset + 1, size), size + 1];
  }
}

export function createVarint(value: number | bigint): Buffer {
  const size = getVarintSize(value);

  value = BigInt(value);

  const buffer = Buffer.alloc(size);
  if (size == 1) {
    buffer[0] = Number(value);
  } else {
    if (size == 3) buffer[0] = 0xfd;
    else if (size === 5) buffer[0] = 0xfe;
    else buffer[0] = 0xff;

    bigintToSmallEndian(value, size - 1, buffer, 1);
  }
  return buffer;
}

export function sanitizeVarintToNumber(n: bigint): number {
  if (n < 0) throw Error('Negative bigint is not a valid varint');
  if (n > Number.MAX_SAFE_INTEGER) throw Error('Too large for a Number');

  return Number(n);
}
