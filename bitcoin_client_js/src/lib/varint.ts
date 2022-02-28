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

/**
 * Converts a `bigint` to a `number` if it non-negative and at most MAX_SAFE_INTEGER; throws `RangeError` otherwise.
 * Used when converting a Bitcoin-style varint to a `number`, since varints could be larger than what the `Number`
 * class can represent without loss of precision.
 *
 * @param n the number to convert
 * @returns `n` as a `number`
 */
 export function sanitizeBigintToNumber(n: number | bigint): number {
  if (n < 0) throw RangeError('Negative bigint is not a valid varint');
  if (n > Number.MAX_SAFE_INTEGER) throw RangeError('Too large for a Number');

  return Number(n);
}

function getVarintSize(value: number | bigint): 1 | 3 | 5 | 9 {
  if (typeof value == 'number') {
    value = sanitizeBigintToNumber(value);
  }

  if (value < BigInt(0)) {
    throw new RangeError('Negative numbers are not supported');
  }

  if (value >= BigInt(1) << BigInt(64)) {
    throw new RangeError('Too large for a Bitcoin-style varint');
  }

  if (value < BigInt(0xfd)) return 1;
  else if (value <= BigInt(0xffff)) return 3;
  else if (value <= BigInt(0xffffffff)) return 5;
  else return 9;
}

/**
 * Parses a Bitcoin-style variable length integer from a buffer, starting at the given `offset`. Returns a pair
 * containing the parsed `BigInt`, and its length in bytes from the buffer.
 *
 * @param data the `Buffer` from which the variable-length integer is read
 * @param offset a non-negative offset to read from
 * @returns a pair where the first element is the parsed BigInt, and the second element is the length in bytes parsed
 * from the buffer.
 *
 * @throws `RangeError` if offset is negative.
 * @throws `Error` if the buffer's end is reached withut parsing being completed.
 */
export function parseVarint(
  data: Buffer,
  offset: number
): readonly [bigint, number] {
  if (offset < 0) {
    throw RangeError("Negative offset is invalid");
  }
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
  if (typeof value == 'number') {
    value = sanitizeBigintToNumber(value);
  }

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
