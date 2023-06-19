import bippath from 'bip32-path'; // TODO: get rid of this dependency
import bs58check from 'bs58check';

export function pathElementsToBuffer(paths: readonly number[]): Buffer {
  const buffer = Buffer.alloc(1 + paths.length * 4);
  buffer[0] = paths.length;
  paths.forEach((element, index) => {
    buffer.writeUInt32BE(element, 1 + 4 * index);
  });
  return buffer;
}

export function bip32asBuffer(path: string): Buffer {
  const pathElements = !path ? [] : pathStringToArray(path);
  return pathElementsToBuffer(pathElements);
}

export function pathArrayToString(pathElements: readonly number[]): string {
  // bippath doesn't handle an empty path.
  if (pathElements.length == 0) {
    return "m";
  }
  return bippath.fromPathArray(pathElements).toString();
}

export function pathStringToArray(path: string): readonly number[] {
  // bippath doesn't handle an empty path.
  if (path == "m" || path == "") {
    return [];
  }
  return bippath.fromString(path).toPathArray();
}

export function pubkeyFromXpub(xpub: string): Buffer {
  const xpubBuf = Buffer.from(bs58check.decode(xpub));
  return xpubBuf.slice(xpubBuf.length - 33);
}

export function getXpubComponents(xpub: string): {
  readonly chaincode: Buffer;
  readonly pubkey: Buffer;
  readonly version: number;
} {
  const xpubBuf = Buffer.from(bs58check.decode(xpub));
  return {
    chaincode: xpubBuf.slice(13, 13 + 32),
    pubkey: xpubBuf.slice(xpubBuf.length - 33),
    version: xpubBuf.readUInt32BE(0),
  };
}

export function hardenedPathOf(
  pathElements: readonly number[]
): readonly number[] {
  for (let i = pathElements.length - 1; i >= 0; i--) {
    if (pathElements[i] >= 0x80000000) {
      return pathElements.slice(0, i + 1);
    }
  }
  return [];
}
