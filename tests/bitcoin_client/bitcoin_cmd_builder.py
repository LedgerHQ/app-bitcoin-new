import enum
import logging
import struct
from typing import List, Tuple, Union, Iterator, cast

from bitcoin_client.transaction import Transaction
from bitcoin_client.utils import bip32_path_from_string

MAX_APDU_LEN: int = 255


def chunkify(data: bytes, chunk_len: int) -> Iterator[Tuple[bool, bytes]]:
    size: int = len(data)

    if size <= chunk_len:
        yield True, data
        return

    chunk: int = size // chunk_len
    remaining: int = size % chunk_len
    offset: int = 0

    for i in range(chunk):
        yield False, data[offset:offset + chunk_len]
        offset += chunk_len

    if remaining:
        yield True, data[offset:]


class BitcoinInsType(enum.IntEnum):
    GET_PUBKEY = 0x00
    GET_ADDRESS = 0x01
    REGISTER_WALLET = 0x02
    GET_SUM_OF_SQUARES = 0xF0

class FrameworkInsType(enum.IntEnum):
    CONTINUE_INTERRUPTED = 0x01

class AddrType(enum.IntEnum):
    """Type of Bitcoin address."""

    PKH = 0x00
    SH_WPKH = 0x01
    WPKH = 0x02

class ClientCommandCode(enum.IntEnum):
    GET_SQUARE = 0x01

class BitcoinCommandBuilder:
    """APDU command builder for the Bitcoin application.

    Parameters
    ----------
    debug: bool
        Whether you want to see logging or not.

    Attributes
    ----------
    debug: bool
        Whether you want to see logging or not.

    """
    CLA_BITCOIN: int = 0xE1
    CLA_FRAMEWORK: int = 0xFE

    def __init__(self, debug: bool = False):
        """Init constructor."""
        self.debug = debug

    def serialize(self,
                  cla: int,
                  ins: Union[int, enum.IntEnum],
                  p1: int = 0,
                  p2: int = 0,
                  cdata: bytes = b"") -> bytes:
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
        bytes
            Bytes of a complete APDU command.

        """
        ins = cast(int, ins.value) if isinstance(ins, enum.IntEnum) else cast(int, ins)

        header: bytes = struct.pack("BBBBB",
                                    cla,
                                    ins,
                                    p1,
                                    p2,
                                    len(cdata))  # add Lc to APDU header

        if self.debug:
            logging.info("header: %s", header.hex())
            logging.info("cdata:  %s", cdata.hex())

        return header + cdata


    def get_pubkey(self, bip32_path: List[int], display: bool = False):
        bip32_paths: List[bytes] = bip32_path_from_string(bip32_path)

        cdata: bytes = b"".join([
            len(bip32_paths).to_bytes(1, byteorder="big"),
            *bip32_paths
        ])

        return self.serialize(cla=self.CLA_BITCOIN,
                        ins=BitcoinInsType.GET_PUBKEY,
                        p1=1 if display else 0,
                        cdata=cdata)

    def get_address(self, addr_type: AddrType, bip32_path: List[int], display: bool = False):
        bip32_paths: List[bytes] = bip32_path_from_string(bip32_path)

        cdata: bytes = b"".join([
            len(bip32_paths).to_bytes(1, byteorder="big"),
            *bip32_paths
        ])

        return self.serialize(cla=self.CLA_BITCOIN,
                        p1=1 if display else 0,
                        p2=addr_type,
                        ins=BitcoinInsType.GET_ADDRESS,
                        cdata=cdata)

    def register_wallet(self, wallet_type: int, name: str, threshold: int, n_keys:int, pubkeys: List[str]):
        cdata: bytes = b"".join([
            wallet_type.to_bytes(1, byteorder="big"),
            len(name).to_bytes(1, byteorder="big"),
            name.encode("latin-1"), # TODO: check appropriate encoding
            threshold.to_bytes(1, byteorder="big"),
            n_keys.to_bytes(1, byteorder="big"),
        ])

        return self.serialize(cla=self.CLA_BITCOIN,
                        p1=0,
                        p2=0,
                        ins=BitcoinInsType.REGISTER_WALLET,
                        cdata=cdata)

    def get_sum_of_squares(self, n: int):
        """Command builder for GET_SUM_OF_SQUARES.

        Returns
        -------
        bytes
            APDU command for GET_SUM_OF_SQUARES.

        """
        return self.serialize(cla=self.CLA_BITCOIN,
                              ins=BitcoinInsType.GET_SUM_OF_SQUARES,
                              cdata=n.to_bytes(1, byteorder="big"))


    def continue_interrupted(self, cdata: bytes):
        """Command builder for CONTINUE.

        Returns
        -------
        bytes
            APDU command for CONTINUE.

        """
        return self.serialize(cla=self.CLA_FRAMEWORK,
                        ins=FrameworkInsType.CONTINUE_INTERRUPTED,
                        cdata=cdata)