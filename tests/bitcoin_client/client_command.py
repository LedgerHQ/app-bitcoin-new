from enum import IntEnum
from typing import List, Mapping, Iterable

from .common import ByteStreamParser
from .key import ExtendedKey
from .merkle import MerkleTree, element_hash

# TODO: The current version treats all client commands individually, forcing the code of each command in command.py
#       to explicitly handle the specific commands that are enabled for their specific needs. It might be easier to
#       instead have a ClientCommandInterpreter that is aware of all the client commands, and has utility functions
#       to manage the client side state (e.g.: the known hashes and Merkle trees).

class ClientCommandCode(IntEnum):
    GET_PUBKEY_INFO = 0x01
    GET_PUBKEYS_IN_DERIVATION_ORDER = 0x20
    GET_PREIMAGE = 0x40
    GET_MERKLE_LEAF_PROOF = 0x41
    GET_MERKLE_LEAF_INDEX = 0x42
    GET_MORE_ELEMENTS = 0xA0


class ClientCommand:
    def execute(self, request: bytes) -> bytes:
        raise NotImplementedError("Subclasses should implement this method.")

    @property
    def code(self) -> int:
        raise NotImplementedError("Subclasses should implement this method.")


class GetPreimageCommand(ClientCommand):
    def __init__(self, known_images: Mapping[bytes, bytes]):
        if any(len(k) != 20 for k in known_images.keys()):
            raise ValueError("RIPEMD160 hashes must be exactly 20 bytes long.")

        if any(len(v) > 254 for v in known_images.values()):
            raise ValueError("Supported preimages are at most 254 bytes long.")

        self.known_images = known_images

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_PREIMAGE

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])
        hash = req.read_bytes(20)
        req.assert_empty()

        for known_hash, known_preimage in self.known_images.items():
            if hash == known_hash:
                return len(known_preimage).to_bytes(1, byteorder="big") + known_preimage

        # not found
        raise RuntimeError(f"Requested unknown preimage for: {hex(hash)}")


class GetMerkleLeafHashCommand(ClientCommand):
    def __init__(self, elements_lists: List[Iterable[bytes]], queue: "deque[bytes]"):
        self.roots_map = {}
        self.queue = queue

        for elements in elements_lists:
            if any(len(el) > 254 for el in elements):
                raise ValueError("Supported preimages are at most 254 bytes long.")

            mt = MerkleTree(elements)
            self.roots_map[mt.root] = mt

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_PROOF

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(20)
        tree_size = req.read_uint(4)
        leaf_index = req.read_uint(4)
        req.assert_empty()

        if not root in self.roots_map:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        mt: MerkleTree = self.roots_map[root]

        if leaf_index >= tree_size or len(mt) != tree_size:
            raise ValueError(f"Invalid index or tree size.")

        if len(self.queue) != 0:
            raise RuntimeError("This command should not execute when the queue is not empty.")

        proof = mt.prove_leaf(leaf_index)
        n_proof_elements = len(proof)//20

        # Compute how many elements we can fit in 255 - 20 - 1 - 1 = 233 bytes
        n_response_elements = min(233//20, len(proof))
        n_leftover_elements = len(proof) - n_response_elements

        # Add to the queue any proof elements that do not fit the response
        self.queue.extend(proof[-n_leftover_elements:])

        return b''.join([
            mt.get(leaf_index),
            len(proof).to_bytes(1, byteorder="big"),
            n_proof_elements.to_bytes(1, byteorder="big"),
            *proof[:n_response_elements]
        ])


# TODO: not tested yet
class GetMerkleLeafIndexCommand(ClientCommand):
    def __init__(self, known_trees: Iterable[MerkleTree]):
        self.merkle_trees = {
            mt.root: mt for mt in known_trees
        }

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_INDEX

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(20)
        leaf_hash = req.read_bytes(20)
        req.assert_empty()

        if root not in self.merkle_trees:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        try:
            leaf_index = self.merkle_trees[root].leaves.index()
        except ValueError:
            raise ValueError(f"The Merkle tree with root {root.hex()} does not have a leaf with hash {leaf_hash.hex()}.")

        return leaf_index.to_bytes(4, byteorder="big")


class GetPubkeysInDerivationOrder(ClientCommand):
    def __init__(self, keys_info: List[str]):
        self.keys_info = keys_info
        keys_info_hashes = map(lambda k: element_hash(k.encode("latin-1")), keys_info)
        self.merkle_tree = MerkleTree(keys_info_hashes)

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_PUBKEYS_IN_DERIVATION_ORDER

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(20)

        if root != self.merkle_tree.root:
            raise ValueError(f"Unknown Merkle root: {root.hex()}")

        tree_size = req.read_uint(4)
        if tree_size != len(self.keys_info):
            raise ValueError(f"Invalid tree size: expected {len(self.keys_info)}, not {tree_size}")

        bip32_path_len = req.read_uint(1)

        if not (0 <= bip32_path_len <= 10):
            raise RuntimeError(f"Invalid derivation len: {bip32_path_len}")

        bip32_path = []
        for _ in range(bip32_path_len):
            bip32_path.append(req.read_uint(4))

        if any(bip32_step >= 0x80000000 for bip32_step in bip32_path):
            raise ValueError("Only unhardened derivation steps are allowed.")

        n_key_indexes = req.read_uint(1)

        key_indexes = []
        for _ in range(n_key_indexes):
            key_indexes.append(req.read_uint(1))

        if any(not 0 <= i < tree_size for i in key_indexes):
            raise ValueError("Key index out of range.")

        req.assert_empty()

        # function to sort keys by the corresponding derived pubkey
        def derived_pk(pubkey_info: str) -> int:

            # Remove the key origin info (if present) by looking for the ']' character
            pos = pubkey_info.find(']')
            pubkey_str = pubkey_info if pos == -1 else pubkey_info[pos+1:]

            ext_pubkey = ExtendedKey.deserialize(pubkey_str)
            ext_pubkey = ext_pubkey.derive_pub_path(bip32_path)

            return ext_pubkey.pubkey

        # attach its index to every key
        used_keys = [(i, self.keys_info[i]) for i in key_indexes]
        # sort according to the derived pubkey
        sorted_keys = sorted(used_keys, key=lambda index_key: derived_pk(index_key[1]))

        result = bytearray([n_key_indexes])
        result.extend(idx_key[0] for idx_key in sorted_keys)
        return bytes(result)


class GetMoreElementsCommand(ClientCommand):
    def __init__(self, queue: "deque[bytes]"):
        self.queue = queue

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MORE_ELEMENTS

    def execute(self, request: bytes) -> bytes:
        if len(request) != 1:
            raise ValueError("Wrong request length.")

        if len(self.queue) == 0:
            raise ValueError("No elements to get.")

        element_len = len(self.queue[0])
        if any(len(el) != element_len for el in self.queue):
            raise ValueError("The queue contains elements of different byte length, which is not expected.")

        # pop from the queue, keeping the total response length at most 255

        response_elements = bytearray()

        n_added_elements = 0
        while len(self.queue) > 0 and len(response_elements) + element_len <= 253:
            response_elements.extend(self.queue.popleft())
            n_added_elements += 1

        return b''.join([
            n_added_elements.to_bytes(1, byteorder="big"),
            element_len.to_bytes(1, byteorder="big"),
            bytes(response_elements)
        ])
