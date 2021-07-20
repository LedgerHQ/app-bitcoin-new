"""base58 module.

Original source: git://github.com/joric/brutus.git
which was forked from git://github.com/samrushing/caesure.git

Distributed under the MIT/X11 software license, see the accompanying
file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""

from binascii import hexlify, unhexlify
from typing import List

from .common import sha256, hash256


b58_digits: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def encode(b: bytes) -> str:
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n: int = int('0x0' + hexlify(b).decode('utf8'), 16)

    # Divide that integer into base58
    temp: List[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        temp.append(b58_digits[r])
    res: str = ''.join(temp[::-1])

    # Encode leading zeros as base58 zeros
    czero: int = 0
    pad: int = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res


def decode(s: str) -> bytes:
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n: int = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise ValueError('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h: str = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


def encode_check(b: bytes) -> str:
    """Encode bytes to a base58-encoded string with checksum"""

    checksum = hash256(b)[0:4]
    return encode(b + checksum)


def decode_check(b: bytes) -> str:
    result_check = decode(b)
    if len(result_check) < 4:
        ValueError("base58 string is too short to have a checksum")

    result, checksum = result_check[:-4], result_check[-4:]

    if hash256(result)[0:4] != checksum:
        raise ValueError("Checksum failed")

    return result
