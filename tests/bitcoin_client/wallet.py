from enum import Enum
from typing import List

from hashlib import sha256

from .utils import serialize_str

class WalletType(Enum):
    MULTISIG = 0

# should not be instantiated directly
class Wallet:
    def __init__(self, name: str, wallet_type: WalletType) -> None:
        if len(name.encode("latin-1")) > 16:
            raise ValueError("The length of name must be at most 16 bytes")

        self.name = name
        self.type = wallet_type

    def serialize(self) -> bytes:
        return self.serialize_header()

    def serialize_header(self) -> bytes:
        return b"".join([
            self.type.value.to_bytes(1, byteorder="big"),
            serialize_str(self.name)
        ])

    @property
    def id(self) -> bytes:
        return sha256(self.serialize()).digest()


class MultisigWallet(Wallet):
    def __init__(self, name: str, threshold: int, n_keys: int, pubkeys: List[str]) -> None:
        super().__init__(name, WalletType.MULTISIG)

        if not (1 <= threshold <= n_keys <= 15):
            raise ValueError("Invalid threshold or n_keys")

        if len(pubkeys) != n_keys:
            raise ValueError("pubkeys should have exactly n_keys elements")

        self.threshold = threshold
        self.n_keys = n_keys
        self.pubkeys = pubkeys

    def serialize_header(self) -> bytes:
        return b"".join([
            super().serialize_header(),
            self.threshold.to_bytes(1, byteorder="big"),
            self.n_keys.to_bytes(1, byteorder="big")
        ])

    def serialize(self) -> bytes:
        return b"".join([
            super().serialize(),
            b''.join(serialize_str(key) for key in self.pubkeys)
        ])
