import re

from enum import IntEnum
from typing import List, Union

from hashlib import sha256

from .common import serialize_str, AddressType, write_varint
from .merkle import MerkleTree, element_hash


class WalletType(IntEnum):
    WALLET_POLICY_V1 = 1
    WALLET_POLICY_V2 = 2


# should not be instantiated directly
class WalletPolicyBase:
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


class WalletPolicy(WalletPolicyBase):
    """
    Represents a wallet stored with a wallet policy.
    For version V2, the wallet is serialized as follows:
       - 1 byte   : wallet version
       - 1 byte   : length of the wallet name (max 64)
       - (var)    : wallet name (ASCII string)
       - (varint) : length of the descriptor template
       - 32-bytes : sha256 hash of the descriptor template
       - (varint) : number of keys (not larger than 252)
       - 32-bytes : root of the Merkle tree of all the keys information.

    The specific format of the keys is deferred to subclasses.
    """

    def __init__(self, name: str, descriptor_template: str, keys_info: List[str], version: WalletType = WalletType.WALLET_POLICY_V2):
        super().__init__(name, version)
        self.descriptor_template = descriptor_template
        self.keys_info = keys_info

    @property
    def n_keys(self) -> int:
        return len(self.keys_info)

    def serialize(self) -> bytes:
        keys_info_hashes = map(
            lambda k: element_hash(k.encode()), self.keys_info)

        descriptor_template_sha256 = sha256(
            self.descriptor_template.encode()).digest()

        return b"".join([
            super().serialize(),
            write_varint(len(self.descriptor_template.encode())),
            self.descriptor_template.encode(
            ) if self.version == WalletType.WALLET_POLICY_V1 else descriptor_template_sha256,
            write_varint(len(self.keys_info)),
            MerkleTree(keys_info_hashes).root
        ])

    def get_descriptor(self, change: Union[bool, None]) -> str:
        """
        Generates a descriptor string based on the wallet's descriptor template and keys.
        Args:
            change (bool | None): Indicates whether the descriptor is for a change address.
                                  - If None, returns the BIP-389 multipath address for both the receive and change address.
                                  - If True, the descriptor is for a change address.
                                  - If False, the descriptor is for a non-change address.
        Returns:
            str: The generated descriptor.
        """

        desc = self.descriptor_template
        for i in reversed(range(self.n_keys)):
            key = self.keys_info[i]
            desc = desc.replace(f"@{i}", key)

        # in V1, /** is part of the key; in V2, it's part of the policy map. This handles either
        if change is not None:
            desc = desc.replace("/**", f"/{1 if change else 0}/*")
        else:
            desc = desc.replace("/**", f"/<0;1>/*")

        if self.version == WalletType.WALLET_POLICY_V2:
            # V2, the /<M;N> syntax is supported. Replace with M if not change, or with N if change
            if change is not None:
                desc = re.sub(r"/<(\d+);(\d+)>", "/\\2" if change else "/\\1", desc)

        return desc


class MultisigWallet(WalletPolicy):
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

        descriptor_template = "".join([
            policy_prefix,
            str(threshold) + ",",
            ",".join("@" + str(l) + key_placeholder_suffix for l in range(n_keys)),
            policy_suffix
        ])

        super().__init__(name, descriptor_template, keys_info, version)

        self.threshold = threshold
