from enum import IntEnum
from typing import List

from hashlib import sha256

from .common import serialize_str, AddressType, write_varint
from .merkle import MerkleTree, element_hash

class WalletType(IntEnum):
    WALLET_POLICY_V1 = 1
    WALLET_POLICY_V2 = 2


# should not be instantiated directly
class Wallet:
    def __init__(self, name: str, version: WalletType) -> None:
        self.name = name
        self.version = version

        if (version != WalletType.WALLET_POLICY_V1 and version != WalletType.WALLET_POLICY_V2):
            raise ValueError("Invalid wallet policy version")

    def serialize(self) -> bytes:
        return b"".join([
            self.version.value.to_bytes(1, byteorder="big"),
            serialize_str(self.name)
        ])

    @property
    def id(self) -> bytes:
        return sha256(self.serialize()).digest()


class PolicyMapWallet(Wallet):
    """
    Represents a wallet stored with a wallet policy.
    For version V2, the wallet is serialized as follows:
       - 1 byte   : wallet version
       - 1 byte   : length of the wallet name (max 16)
       - (var)    : wallet name (ASCII string)
       - (varint) : length of the descriptor template
       - 32-bytes : sha256 hash of the descriptor template
       - (varint) : number of keys (not larger than 252)
       - 32-bytes : root of the Merkle tree of all the keys information.

    The specific format of the keys is deferred to subclasses.
    """

    def __init__(self, name: str, policy_map: str, keys_info: List[str], version: WalletType = WalletType.WALLET_POLICY_V2):
        super().__init__(name, version)
        self.policy_map = policy_map
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def serialize(self) -> bytes:
        keys_info_hashes = map(lambda k: element_hash(k.encode()), self.keys_info)

        policy_map_sha256 = sha256(self.policy_map.encode()).digest()

        return b"".join([
            super().serialize(),
            write_varint(len(self.policy_map.encode())),
            self.policy_map.encode() if self.version == WalletType.WALLET_POLICY_V1 else policy_map_sha256,
            write_varint(len(self.keys_info)),
            MerkleTree(keys_info_hashes).root
        ])

    def get_descriptor(self, change: bool) -> str:
        desc = self.policy_map
        for i in reversed(range(self.n_keys)):
            key = self.keys_info[i]
            desc = desc.replace(f"@{i}", key)

        # in V1, /** is part of the key; in V1, it's part of the policy map. This handles either
        return desc.replace("/**", f"/{1 if change else 0}/*")

class MultisigWallet(PolicyMapWallet):
    def __init__(self, name: str, address_type: AddressType, threshold: int, keys_info: List[str], sorted: bool = True, version: WalletType = WalletType.WALLET_POLICY_V2) -> None:
        n_keys = len(keys_info)

        if not (1 <= threshold <= n_keys <= 16):
            raise ValueError("Invalid threshold or number of keys")

        multisig_op = "sortedmulti" if sorted else "multi"

        if (address_type == AddressType.LEGACY):
            policy_prefix = f"sh({multisig_op}("
            policy_suffix = f"))"
        elif address_type == AddressType.WIT:
            policy_prefix = f"wsh({multisig_op}("
            policy_suffix = f"))"
        elif address_type == AddressType.SH_WIT:
            policy_prefix = f"sh(wsh({multisig_op}("
            policy_suffix = f")))"
        else:
            raise ValueError(f"Unexpected address type: {address_type}")

        key_placeholder_suffix = "/**" if version == WalletType.WALLET_POLICY_V2 else ""

        policy_map = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("@" + str(l) + key_placeholder_suffix for l in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, policy_map, keys_info, version)

        self.threshold = threshold
