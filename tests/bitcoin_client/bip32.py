import hmac
import ecdsa
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
import hashlib

from . import base58
from .utils import ripemd160, hash160, hash256

BIP32_FIRST_HARDENED_CHILD = 0x80000000

# Secp256k1 curve parameters
SECP256k1_p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f


def get_uncompressed_pubkey(compressed_pubkey: bytes) -> Point:
    if len(compressed_pubkey) != 33 or compressed_pubkey[0] not in [0x02, 0x03]:
        raise ValueError(f"compressed_pubkey must be exactly 33 bytes long and start with 0x02 or 0x03")

    x_bytes = compressed_pubkey[1:]
    x = int.from_bytes(x_bytes, byteorder="big")
    y_sq = (x**3 + 7) % SECP256k1_p
    y = pow(y_sq, (SECP256k1_p + 1) // 4, SECP256k1_p)

    # we use the fact that y and the first byte of compressed_pubkey must have the same parity
    # to select the correct square root for y
    if (compressed_pubkey[0] % 2 != y % 2):
        y = SECP256k1_p - y

    return Point(SECP256k1.curve, x, y, SECP256k1.order)


class ExtendedPubkey:
    def __init__(self, version: bytes, depth: int, parent_fingerprint: bytes, child_number: int, chain_code: bytes, compressed_pubkey: bytes):
        if len(version) != 4:
            raise ValueError("version must be exactly 4 bytes long")
        if not 0 <= depth <= 255:
            raise ValueError("depth must be between 0 and 255")
        if len(parent_fingerprint) != 4:
            raise ValueError(f"parent_fingerprint must be exactly 4 bytes long")
        if not 0 <= child_number < 2^32:
            raise ValueError(f"child_number must be a 32-bit integer")
        if len(chain_code) != 32:
            raise ValueError(f"chain_code must be exactly 32 bytes long")
        if len(compressed_pubkey) != 33 or compressed_pubkey[0] not in [0x02, 0x03]:
            raise ValueError(f"compressed_pubkey must be exactly 33 bytes long and start with 0x02 or 0x03")

        self.version = version
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.chain_code = chain_code
        self.compressed_pubkey = compressed_pubkey

    @staticmethod
    def from_base58(pubkey: str) -> 'ExtendedPubkey':
        """Creates an instance from a base58check-encoded extended pubkey"""

        raw_pubkey = base58.decode_check(pubkey)

        if len(raw_pubkey) != 78:
            raise ValueError("Invalid pubkey")

        return ExtendedPubkey(
            version=raw_pubkey[0:4],
            depth=int(raw_pubkey[4]),
            parent_fingerprint=raw_pubkey[5:9],
            child_number=int.from_bytes(raw_pubkey[9:13], byteorder="big"),
            chain_code=raw_pubkey[13:45],
            compressed_pubkey=raw_pubkey[45:78]
        )

    def serialize(self) -> str:
        """Serializes this extended public key in base58check encoding"""

        return base58.encode_check(b''.join([
            self.version,
            self.depth.to_bytes(1, byteorder="big"),
            self.parent_fingerprint,
            self.child_number.to_bytes(4, byteorder="big"),
            self.chain_code,
            self.compressed_pubkey
        ]))

    def derive_child(self, child_index):
        """Derives an unhardened public key (CKDpub function of BIP-32)"""

        if child_index >= BIP32_FIRST_HARDENED_CHILD:
            raise ValueError("Can only do unhardened derivation (child_index < 0x80000000)")

        if self.depth == 255:
            raise ValueError("Cannot derive from a parent with depth 255")

        I = hmac.new(
            key = self.chain_code,
            msg = self.compressed_pubkey + child_index.to_bytes(4, "big"),
            digestmod = hashlib.sha512
        ).digest()

        I_L, I_R = I[:32], I[32:]

        K_par = get_uncompressed_pubkey(self.compressed_pubkey)

        # child uncompressed pubkey and chain code
        K_i = (ecdsa.SECP256k1.generator * int.from_bytes(I_L, byteorder="big") + K_par).to_affine()
        c_i = I_R

        prefix = b"\x02" if K_i.y() % 2 == 0 else b"\x03"
        K_i_compressed = prefix + int(K_i.x()).to_bytes(32, byteorder="big")

        parent_fingerprint = hash160(self.compressed_pubkey)[:4]

        return ExtendedPubkey(
            version = self.version,
            depth = self.depth + 1,
            parent_fingerprint = parent_fingerprint,
            child_number = child_index,
            chain_code = c_i,
            compressed_pubkey = K_i_compressed
        )
