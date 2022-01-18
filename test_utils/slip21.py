from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

"""Bare-bones implementation of SLIP-0021: https://github.com/satoshilabs/slips/blob/master/slip-0021.md."""

SLIP21_MASTER_NODE_KEY = b"Symmetric key seed"


@dataclass
class Slip21Node:
    chain_code: bytes
    key: bytes

    @staticmethod
    def from_seed(seed: bytes) -> Slip21Node:
        h = hmac.new(SLIP21_MASTER_NODE_KEY, seed, hashlib.sha512).digest()
        return Slip21Node(h[0:32], h[32:64])

    def derive_child(self, label: bytes) -> Slip21Node:
        h = hmac.new(self.chain_code, b'\0' + label, hashlib.sha512).digest()
        return Slip21Node(h[0:32], h[32:64])
