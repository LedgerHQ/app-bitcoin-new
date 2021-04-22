from enum import IntEnum
from typing import List

from hashlib import sha256

from .common import serialize_str, AddressType
from .merkle import MerkleTree, element_hash

class WalletType(IntEnum):
    MULTISIG = 1


# should not be instantiated directly
class Wallet:
    def __init__(self, name: str, wallet_type: WalletType) -> None:
        if len(name.encode("latin-1")) > 16:
            raise ValueError("The length of name must be at most 16 bytes")

        self.name = name
        self.type = wallet_type

    def serialize(self) -> bytes:
        return b"".join([
            self.type.value.to_bytes(1, byteorder="big"),
            serialize_str(self.name)
        ])

    @property
    def id(self) -> bytes:
        return sha256(self.serialize()).digest()


class PolicyMapWallet(Wallet):
    """
    Represents a wallet stored with a policy map and a number of keys_info.
    The wallet is serialized as:
       - 2 bytes: length of the policy map, encoded in big-endian
       - (variable): policy map
       - 20-bytes Merkle root of the Merkle tree of all the keys information.
    
    The specific format of the keys is deferred to subclasses.
    """

    def __init__(self, name: str, wallet_type: WalletType, policy_map: str, keys_info: List[str]):
        super().__init__(name, wallet_type)
        self.policy_map = policy_map
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def serialize(self) -> bytes:
        keys_info_hashes = map(lambda k: element_hash(k.encode("latin-1")), self.keys_info)

        return b"".join([
            super().serialize(),
            len(self.policy_map).to_bytes(2, byteorder="big"),
            self.policy_map.encode("latin-1"),
            len(self.keys_info).to_bytes(2, byteorder="big"),
            MerkleTree(keys_info_hashes).root
        ])


class MultisigWallet(PolicyMapWallet):
    def __init__(self, name: str, address_type: AddressType, threshold: int, keys_info: List[str], sorted: bool = True) -> None:
        n_keys = len(keys_info)

        if not (1 <= threshold <= n_keys <= 15):
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

        policy_map = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("\t" + str(l) for l in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, WalletType.MULTISIG, policy_map, keys_info)

        self.threshold = threshold
