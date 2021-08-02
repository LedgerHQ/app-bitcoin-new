from enum import IntEnum
from typing import List, Mapping, Iterable
from collections import deque
from hashlib import sha256

from bitcoin_client.common import ByteStreamParser, ripemd160, write_varint
from bitcoin_client.merkle import MerkleTree, element_hash


class ClientCommandCode(IntEnum):
    YIELD = 0x10
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


class YieldCommand(ClientCommand):
    def __init__(self, results: List[bytes]):
        self.results = results

    @property
    def code(self) -> int:
        return ClientCommandCode.YIELD

    def execute(self, request: bytes) -> bytes:
        self.results.append(request[1:])  # only skip the first byte (command code)
        return b""


class GetPreimageCommand(ClientCommand):
    def __init__(self, known_preimages: Mapping[bytes, bytes], queue: "deque[bytes]"):
        self.queue = queue
        self.known_preimages = known_preimages

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_PREIMAGE

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])
        req_hash = req.read_bytes(20)
        req.assert_empty()

        for known_hash, known_preimage in self.known_preimages.items():
            if req_hash == known_hash:
                preimage_len_out = write_varint(len(known_preimage))

                # We can send at most 255 - len(preimage_len_out) - 1 bytes in a single message;
                # the rest will be stored for GET_MORE_ELEMENTS

                max_payload_size = 255 - len(preimage_len_out) - 1

                payload_size = min(max_payload_size, len(known_preimage))

                if payload_size < len(known_preimage):
                    # split into list of length-1 bytes elements
                    extra_elements = [
                        known_preimage[i: i + 1]
                        for i in range(payload_size, len(known_preimage))
                    ]
                    # add to the queue any remaining extra bytes
                    self.queue.extend(extra_elements)

                return (
                    preimage_len_out
                    + payload_size.to_bytes(1, byteorder="big")
                    + known_preimage[:payload_size]
                )

        # not found
        raise RuntimeError(f"Requested unknown preimage for: {req_hash.hex()}")


class GetMerkleLeafHashCommand(ClientCommand):
    def __init__(self, known_trees: Mapping[bytes, MerkleTree], queue: "deque[bytes]"):
        self.queue = queue
        self.known_trees = known_trees

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_PROOF

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(20)
        tree_size = req.read_uint(4)
        leaf_index = req.read_uint(4)
        req.assert_empty()

        if not root in self.known_trees:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        mt: MerkleTree = self.known_trees[root]

        if leaf_index >= tree_size or len(mt) != tree_size:
            raise ValueError(f"Invalid index or tree size.")

        if len(self.queue) != 0:
            raise RuntimeError(
                "This command should not execute when the queue is not empty."
            )

        proof = mt.prove_leaf(leaf_index)
        n_proof_elements = len(proof) // 20

        # Compute how many elements we can fit in 255 - 20 - 1 - 1 = 233 bytes
        n_response_elements = min(233 // 20, len(proof))
        n_leftover_elements = len(proof) - n_response_elements

        # Add to the queue any proof elements that do not fit the response
        self.queue.extend(proof[-n_leftover_elements:])

        return b"".join(
            [
                mt.get(leaf_index),
                len(proof).to_bytes(1, byteorder="big"),
                n_proof_elements.to_bytes(1, byteorder="big"),
                *proof[:n_response_elements],
            ]
        )


class GetMerkleLeafIndexCommand(ClientCommand):
    def __init__(self, known_trees: Mapping[bytes, MerkleTree]):
        self.known_trees = known_trees

    @property
    def code(self) -> int:
        return ClientCommandCode.GET_MERKLE_LEAF_INDEX

    def execute(self, request: bytes) -> bytes:
        req = ByteStreamParser(request[1:])

        root = req.read_bytes(20)
        leaf_hash = req.read_bytes(20)
        req.assert_empty()

        if root not in self.known_trees:
            raise ValueError(f"Unknown Merkle root: {root.hex()}.")

        try:
            leaf_index = self.known_trees[root].leaf_index(leaf_hash)
            found = 1
        except ValueError:
            leaf_index = 0
            found = 0

        return found.to_bytes(1, byteorder="big") + write_varint(leaf_index)


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
            raise ValueError(
                "The queue contains elements of different byte length, which is not expected."
            )

        # pop from the queue, keeping the total response length at most 255

        response_elements = bytearray()

        n_added_elements = 0
        while len(self.queue) > 0 and len(response_elements) + element_len <= 253:
            response_elements.extend(self.queue.popleft())
            n_added_elements += 1

        return b"".join(
            [
                n_added_elements.to_bytes(1, byteorder="big"),
                element_len.to_bytes(1, byteorder="big"),
                bytes(response_elements),
            ]
        )


class ClientCommandInterpreter:
    # TODO: should we enable a constructor to only pass a subset of the commands?
    def __init__(self):
        self.known_preimages: Mapping[bytes, bytes] = {}
        self.known_trees: Mapping[bytes, MerkleTree] = {}
        self.known_keylists: Mapping[bytes, List[str]] = {}

        self.yielded: List[bytes] = []

        queue = deque()

        commands = [
            YieldCommand(self.yielded),
            GetPreimageCommand(self.known_preimages, queue),
            GetMerkleLeafIndexCommand(self.known_trees),
            GetMerkleLeafHashCommand(self.known_trees, queue),
            GetMoreElementsCommand(queue),
        ]

        self.commands = {cmd.code: cmd for cmd in commands}

    def execute(self, hw_response: bytes) -> bytes:
        if len(hw_response) == 0:
            raise RuntimeError(
                "Unexpected empty SW_INTERRUPTED_EXECUTION response from hardware wallet."
            )

        cmd_code = hw_response[0]
        if cmd_code not in self.commands:
            raise RuntimeError(
                "Unexpected command code: 0x{:02X}".format(cmd_code)
            )  # TODO: more precise Error type

        return self.commands[cmd_code].execute(hw_response)

    def add_known_preimage(self, element: bytes):
        self.known_preimages[ripemd160(element)] = element

    def add_known_list(self, elements: List[bytes]):
        for el in elements:
            self.add_known_preimage(b"\x00" + el)

        mt = MerkleTree(element_hash(el) for el in elements)

        self.known_trees[mt.root] = mt

    def add_known_pubkey_list(self, keys_info: List[str]):
        elements_encoded = [key_info.encode() for key_info in keys_info]
        self.add_known_list(elements_encoded)

        mt = MerkleTree(element_hash(el) for el in elements_encoded)
        self.known_keylists[mt.root] = keys_info

    def add_known_mapping(self, mapping: Mapping[bytes, bytes]):
        items_sorted = list(sorted(mapping.items()))

        keys = [i[0] for i in items_sorted]
        values = [i[1] for i in items_sorted]
        self.add_known_list(keys)
        self.add_known_list(values)
