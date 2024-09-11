import enum
from typing import List, Tuple, Mapping, Union, Iterator, Optional

from .common import bip32_path_from_string, write_varint
from .merkle import get_merkleized_map_commitment, MerkleTree, element_hash
from .withdraw import AcreWithdrawalDataBytes
from .wallet import WalletPolicy

# p2 encodes the protocol version implemented
CURRENT_PROTOCOL_VERSION = 1

def chunkify(data: bytes, chunk_len: int) -> Iterator[Tuple[bool, bytes]]:
    size: int = len(data)

    if size <= chunk_len:
        yield True, data
        return

    chunk: int = size // chunk_len
    remaining: int = size % chunk_len
    offset: int = 0

    for i in range(chunk):
        yield False, data[offset: offset + chunk_len]
        offset += chunk_len

    if remaining:
        yield True, data[offset:]


class DefaultInsType(enum.IntEnum):
    GET_VERSION = 0x01

class BitcoinInsType(enum.IntEnum):
    GET_EXTENDED_PUBKEY = 0x00
    REGISTER_WALLET = 0x02
    GET_WALLET_ADDRESS = 0x03
    SIGN_PSBT = 0x04
    GET_MASTER_FINGERPRINT = 0x05
    SIGN_MESSAGE = 0x10
    SIGN_WITHDRAW = 0x11

class FrameworkInsType(enum.IntEnum):
    CONTINUE_INTERRUPTED = 0x01


class BitcoinCommandBuilder:
    """APDU command builder for the Bitcoin application."""

    CLA_DEFAULT: int = 0xB0
    CLA_BITCOIN: int = 0xE1
    CLA_FRAMEWORK: int = 0xF8

    def serialize(
        self,
        cla: int,
        ins: Union[int, enum.IntEnum],
        p1: int = 0,
        p2: int = CURRENT_PROTOCOL_VERSION,
        cdata: bytes = b"",
    ) -> dict:
        """Serialize the whole APDU command (header + data).

        Parameters
        ----------
        cla : int
            Instruction class: CLA (1 byte)
        ins : Union[int, IntEnum]
            Instruction code: INS (1 byte)
        p1 : int
            Instruction parameter 1: P1 (1 byte).
        p2 : int
            Instruction parameter 2: P2 (1 byte).
        cdata : bytes
            Bytes of command data.

        Returns
        -------
        dict
            Dictionary representing the APDU message.

        """

        return {"cla": cla, "ins": ins, "p1": p1, "p2": p2, "data": cdata}

    def get_extended_pubkey(self, bip32_path: str, display: bool = False):
        bip32_path: List[bytes] = bip32_path_from_string(bip32_path)

        cdata: bytes = b"".join([
            b'\1' if display else b'\0',
            len(bip32_path).to_bytes(1, byteorder="big"),
            *bip32_path
        ])

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_EXTENDED_PUBKEY,
            cdata=cdata,
        )

    def register_wallet(self, wallet: WalletPolicy):
        wallet_bytes = wallet.serialize()

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.REGISTER_WALLET,
            cdata=write_varint(len(wallet_bytes)) + wallet_bytes,
        )

    def get_wallet_address(
        self,
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
        address_index: int,
        change: bool,
        display: bool,
    ):
        cdata: bytes = b"".join(
            [
                b'\1' if display else b'\0',                            # 1 byte
                wallet.id,                                              # 32 bytes
                wallet_hmac if wallet_hmac is not None else b'\0' * 32, # 32 bytes
                b"\1" if change else b"\0",                             # 1 byte
                address_index.to_bytes(4, byteorder="big"),             # 4 bytes
            ]
        )

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_WALLET_ADDRESS,
            cdata=cdata,
        )

    def sign_psbt(
        self,
        global_mapping: Mapping[bytes, bytes],
        input_mappings: List[Mapping[bytes, bytes]],
        output_mappings: List[Mapping[bytes, bytes]],
        wallet: WalletPolicy,
        wallet_hmac: Optional[bytes],
    ):

        cdata = bytearray()
        cdata += get_merkleized_map_commitment(global_mapping)

        cdata += write_varint(len(input_mappings))
        cdata += MerkleTree(
            [
                element_hash(get_merkleized_map_commitment(m_in))
                for m_in in input_mappings
            ]
        ).root

        cdata += write_varint(len(output_mappings))
        cdata += MerkleTree(
            [
                element_hash(get_merkleized_map_commitment(m_out))
                for m_out in output_mappings
            ]
        ).root

        cdata += wallet.id
        cdata += wallet_hmac if wallet_hmac is not None else b'\0' * 32

        return self.serialize(
            cla=self.CLA_BITCOIN, ins=BitcoinInsType.SIGN_PSBT, cdata=bytes(cdata)
        )

    def get_master_fingerprint(self):
        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.GET_MASTER_FINGERPRINT
        )

    def sign_message(self, message: bytes, bip32_path: str):
        cdata = bytearray()

        bip32_path: List[bytes] = bip32_path_from_string(bip32_path)

        # split message in 64-byte chunks (last chunk can be smaller)
        n_chunks = (len(message) + 63) // 64
        chunks = [message[64 * i: 64 * i + 64] for i in range(n_chunks)]

        cdata += len(bip32_path).to_bytes(1, byteorder="big")
        cdata += b''.join(bip32_path)

        cdata += write_varint(len(message))

        cdata += MerkleTree(element_hash(c) for c in chunks).root

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.SIGN_MESSAGE,
            cdata=bytes(cdata)
        )
    
    def sign_withdraw(self, data_bytes: AcreWithdrawalDataBytes, bip32_path: str):
        cdata = bytearray()

        bip32_path: List[bytes] = bip32_path_from_string(bip32_path)

        chunks = []

        # Chunk 0: to[20] + gasToken[20] + refundReceiver[20]
        chunks.append(data_bytes.to + data_bytes.gasToken + data_bytes.refundReceiver)

        # Chunk 1: value[32] + safeTxGas[32]
        chunks.append(data_bytes.value + data_bytes.safeTxGas)

        # Chunk 2: baseGas[32] + gasPrice[32]
        chunks.append(data_bytes.baseGas + data_bytes.gasPrice)

        # Chunk 3: nonce[32] + operation[1]
        chunks.append(data_bytes.nonce + data_bytes.operation)

        # Chunk 4: data_selector[4] (the first 4 bytes of data)
        chunks.append(data_bytes.data[:4])

        # Calculate the number of 64-byte chunks needed for the remaining data
        n_chunks_data = (len(data_bytes.data) - 4 + 63) // 64

        # Chunk 5 to n: data[64]
        for i in range(n_chunks_data):
            chunks.append(data_bytes.data[4 + 64 * i: 4 + 64 * (i + 1)])

        cdata += len(bip32_path).to_bytes(1, byteorder="big")
        cdata += b''.join(bip32_path)

        cdata += write_varint(n_chunks_data + 5)

        cdata += MerkleTree(element_hash(c) for c in chunks).root

        return self.serialize(
            cla=self.CLA_BITCOIN,
            ins=BitcoinInsType.SIGN_WITHDRAW,
            cdata=bytes(cdata)
        )

    def continue_interrupted(self, cdata: bytes):
        """Command builder for CONTINUE.

        Returns
        -------
        bytes
            APDU command for CONTINUE.

        """
        return self.serialize(
            cla=self.CLA_FRAMEWORK,
            ins=FrameworkInsType.CONTINUE_INTERRUPTED,
            cdata=cdata,
        )
