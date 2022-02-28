import { createVarint, parseVarint, sanitizeBigintToNumber } from "../lib/varint";

describe("sanitizeBigintToNumber", () => {
  it("throws for negative number", async () => {
    expect(() => sanitizeBigintToNumber(BigInt(-1))).toThrow(RangeError);
    expect(() => sanitizeBigintToNumber(-1)).toThrow(RangeError);
  });

  it("throws RangeError for number too large", async () => {
    // Number.MAX_SAFE_INTEGER is 9007199254740991
    expect(() => sanitizeBigintToNumber(Number.MAX_SAFE_INTEGER + 1)).toThrow(RangeError);
    expect(() => sanitizeBigintToNumber(BigInt("9007199254740992"))).toThrow(RangeError);
  });

  it("correctly sanitizes biginters in range", async () => {
    expect(sanitizeBigintToNumber(BigInt(0))).toEqual(0);
    expect(sanitizeBigintToNumber(BigInt(1))).toEqual(1);
    expect(sanitizeBigintToNumber(BigInt(Number.MAX_SAFE_INTEGER))).toEqual(Number.MAX_SAFE_INTEGER);

    expect(sanitizeBigintToNumber(0)).toEqual(0);
    expect(sanitizeBigintToNumber(1)).toEqual(1);
    expect(sanitizeBigintToNumber(Number.MAX_SAFE_INTEGER)).toEqual(Number.MAX_SAFE_INTEGER);
  });
});


describe("createVarint", () => {
  it("correctly encodes 1-byte varints", async () => {
    expect(createVarint(0)).toEqual(Buffer.from([0]));
    expect(createVarint(BigInt(0))).toEqual(Buffer.from([0]));

    expect(createVarint(1)).toEqual(Buffer.from([1]));
    expect(createVarint(BigInt(1))).toEqual(Buffer.from([1]));

    expect(createVarint(0xfc)).toEqual(Buffer.from([0xfc]));
    expect(createVarint(BigInt(0xfc))).toEqual(Buffer.from([0xfc]));
  });

  it("correctly encodes 3-byte varints", async () => {
    expect(createVarint(0xfd)).toEqual(Buffer.from([0xfd, 0xfd, 0x00]));
    expect(createVarint(BigInt(0xfd))).toEqual(Buffer.from([0xfd, 0xfd, 0x00]));

    expect(createVarint(0xffff)).toEqual(Buffer.from([0xfd, 0xff, 0xff]));
    expect(createVarint(BigInt(0xffff))).toEqual(Buffer.from([0xfd, 0xff, 0xff]));
  });

  it("correctly encodes 5-byte varints", async () => {
    expect(createVarint(0x00010000)).toEqual(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]));
    expect(createVarint(BigInt(0x00010000))).toEqual(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]));

    expect(createVarint(0x12345678)).toEqual(Buffer.from([0xfe, 0x78, 0x56, 0x34, 0x12]));
    expect(createVarint(BigInt(0x12345678))).toEqual(Buffer.from([0xfe, 0x78, 0x56, 0x34, 0x12]));

    expect(createVarint(0xffffffff)).toEqual(Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff]));
    expect(createVarint(BigInt(0xffffffff))).toEqual(Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff]));
  });

  it("correctly encodes 9-byte varints", async () => {
    expect(createVarint(0x100000000)).toEqual(Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));
    expect(createVarint(BigInt(0x100000000))).toEqual(
      Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    );

    expect(createVarint(BigInt("0x0011223344556677"))).toEqual(
      Buffer.from([0xff, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00])
    );

    expect(createVarint(BigInt("0xffffffffffffffff"))).toEqual(
      Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    );
  });

  it("throws RangeError for values out of range", async () => {
    expect(() => createVarint(-1)).toThrow(RangeError);
    expect(() => createVarint(BigInt(-1))).toThrow(RangeError);
    expect(() => createVarint(Number.MAX_SAFE_INTEGER + 1)).toThrow(RangeError);
    expect(() => createVarint(BigInt("0x10000000000000000"))).toThrow(RangeError);
  });
});


describe("parseVarint", () => {
  const NIL = 42; // dummy value to label unused bytes

  it("correctly decodes 1-byte varints", async () => {
    expect(parseVarint(Buffer.from([0]), 0)).toEqual([BigInt(0), 1]);
    expect(parseVarint(Buffer.from([NIL, 0]), 1)).toEqual([BigInt(0), 1]);

    expect(parseVarint(Buffer.from([0xfc]), 0)).toEqual([BigInt(0xfc), 1]);
  });

  it("correctly decodes 3-byte varints", async () => {
    expect(parseVarint(Buffer.from([0xfd, 0xfd, 0x00]), 0)).toEqual([BigInt(0xfd), 3]);
    expect(parseVarint(Buffer.from([0xfd, 0xff, 0xff]), 0)).toEqual([BigInt(0xffff), 3]);
  });

  it("correctly decodes 5-byte varints", async () => {
    expect(parseVarint(Buffer.from([0xfe, 0x00, 0x00, 0x01, 0x00]), 0)).toEqual([BigInt(0x00010000), 5]);
    expect(parseVarint(Buffer.from([0xfe, 0x78, 0x56, 0x34, 0x12]), 0)).toEqual([BigInt(0x12345678), 5]);
    expect(parseVarint(Buffer.from([0xfe, 0xff, 0xff, 0xff, 0xff]), 0)).toEqual([BigInt(0xffffffff), 5]);
  });

  it("correctly decodes 9-byte varints", async () => {
    expect(parseVarint(Buffer.from([0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]), 0)).toEqual(
      [BigInt(0x100000000), 9]
    );

    expect(parseVarint(Buffer.from([0xff, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]), 0)).toEqual(
      [BigInt("0x0011223344556677"), 9]
    );
    expect(parseVarint(Buffer.from([NIL, 0xff, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, NIL]), 1)).toEqual(
      [BigInt("0x0011223344556677"), 9]
    );
    expect(parseVarint(Buffer.from([NIL, NIL, 0xff, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]), 2)).toEqual(
      [BigInt("0x0011223344556677"), 9]
    );

    expect(parseVarint(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), 0)).toEqual(
      [BigInt("0xffffffffffffffff"), 9]
    );
  });

  it("throws RangeError if offset is negative", async () => {
    expect(() => parseVarint(Buffer.from([0x12, 0x34]), -1)).toThrow(RangeError);
  });

  it("throws when the buffer is too small", async () => {
    expect(() => parseVarint(Buffer.from([]), 0)).toThrow(Error);

    expect(() => parseVarint(Buffer.from([0xfd, 0xff]), 0)).toThrow(Error);

    expect(() => parseVarint(Buffer.from([0xfe, 0x78, 0x56, 0x34]), 0)).toThrow(Error);

    expect(() => parseVarint(Buffer.from([NIL, NIL, 0xff, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]), 2)).toThrow(Error);

  });
});
