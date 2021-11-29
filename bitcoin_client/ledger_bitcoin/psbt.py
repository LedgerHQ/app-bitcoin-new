"""
Original version: https://github.com/bitcoin-core/HWI


MIT License

Copyright (c) 2017 Andrew Chow

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


PSBT Classes and Utilities
**************************
"""

import base64
import struct

from io import BytesIO, BufferedReader
from typing import (
    Dict,
    List,
    Tuple,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
)

from .key import KeyOriginInfo
from .errors import PSBTSerializationError
from .tx import (
    CTransaction,
    CTxInWitness,
    CTxOut,
)
from ._serialize import (
    deser_compact_size,
    deser_string,
    Readable,
    ser_compact_size,
    ser_string,
    ser_uint256
)

def DeserializeHDKeypath(
    f: Readable,
    key: bytes,
    hd_keypaths: MutableMapping[bytes, KeyOriginInfo],
    expected_sizes: Sequence[int],
) -> None:
    """
    :meta private:

    Deserialize a serialized PSBT public key and keypath key-value pair.

    :param f: The byte stream to read the value from.
    :param key: The bytes of the key of the key-value pair.
    :param hd_keypaths: Dictionary of public key bytes to their :class:`~hwilib.key.KeyOriginInfo`.
    :param expected_sizes: List of key lengths expected for the keypair being deserialized.
    """
    if len(key) not in expected_sizes:
        raise PSBTSerializationError("Size of key was not the expected size for the type partial signature pubkey. Length: {}".format(len(key)))
    pubkey = key[1:]
    if pubkey in hd_keypaths:
        raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

    hd_keypaths[pubkey] = KeyOriginInfo.deserialize(deser_string(f))

def SerializeHDKeypath(hd_keypaths: Mapping[bytes, KeyOriginInfo], type: bytes) -> bytes:
    """
    :meta private:

    Serialize a public key to :class:`~hwilib.key.KeyOriginInfo` mapping as a PSBT key-value pair.

    :param hd_keypaths: The mapping of public key to keypath
    :param type: The PSBT type bytes to use
    :returns: The serialized keypaths
    """
    r = b""
    for pubkey, path in sorted(hd_keypaths.items()):
        r += ser_string(type + pubkey)
        packed = path.serialize()
        r += ser_string(packed)
    return r

def DeserializeHDHashesKeypath(
    f: Readable,
    key: bytes,
    hashes_hd_keypaths: MutableMapping[bytes, Tuple[List[bytes], KeyOriginInfo]],
    expected_sizes: Sequence[int],
) -> None:
    """
    :meta private:

    Deserialize a serialized PSBT public key and leaf-hashes + keypath key-value pair
    (as the PSBT_IN_TAP_BIP32_DERIVATION and PSBT_OUT_TAP_BIP32_DERIVATION key-value pairs).

    :param f: The byte stream to read the value from.
    :param key: The bytes of the key of the key-value pair.
    :param hashes_hd_keypaths: Dictionary of public key bytes to pairs of lists of hashes and :class:`~hwilib.key.KeyOriginInfo`.
    :param expected_sizes: List of key lengths expected for the keypair being deserialized.
    """
    if len(key) not in expected_sizes:
        raise PSBTSerializationError("Size of key was not the expected size. Length: {}".format(len(key)))

    pubkey = key[1:]
    if pubkey in hashes_hd_keypaths:
        raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

    value = deser_string(f)
    f_value = BufferedReader(BytesIO(value)) # type: ignore

    hashes_len = deser_compact_size(f_value)
    hashes = [f_value.read(32) for _ in range(hashes_len)]

    key_origin_info = KeyOriginInfo.deserialize(f_value.read())

    hashes_hd_keypaths[pubkey] = (hashes, key_origin_info)

def SerializeHDHashesKeypath(hashes_hd_keypaths: Mapping[bytes, Tuple[List[bytes], KeyOriginInfo]], type: bytes) -> bytes:
    """
    :meta private:

    Serialize a public key to pairs of leaf-hashes + :class:`~hwilib.key.KeyOriginInfo` mapping as a PSBT key-value pair.
    Used for PSBT_IN_TAP_BIP32_DERIVATION and PSBT_OUT_TAP_BIP32_DERIVATION key-value pairs.

    :param hashes_hd_keypaths: The mapping of public key to keypath
    :param type: The PSBT type bytes to use
    :returns: The serialized keypaths
    """
    r = b""
    for pubkey, hashes_path in sorted(hashes_hd_keypaths.items()):
        hashes, path = hashes_path
        r += ser_string(type + pubkey)

        value = b"".join([
            ser_compact_size(len(hashes)),
            *hashes,
            path.serialize()
        ])

        r += ser_string(value)
    return r


class PartiallySignedInput:
    """
    An object for a PSBT input map.
    """

    def __init__(self) -> None:
        self.non_witness_utxo: Optional[CTransaction] = None
        self.witness_utxo: Optional[CTxOut] = None
        self.partial_sigs: Dict[bytes, bytes] = {}
        self.sighash = 0
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()

        # psbt2 extensions
        self.previous_txid: Optional[bytes] = None
        self.output_index: Optional[int] = None
        self.sequence: Optional[int] = None
        self.required_time_locktime: Optional[int] = None
        self.required_height_locktime: Optional[int] = None

        # taproot fields
        self.tap_key_sig: bytes = b""
        # self.tap_script_sig = # Not implemented
        # self.tap_leaf_script = # Not implemented
        self.tap_hd_keypaths: Dict[bytes, Tuple[List[bytes], KeyOriginInfo]] = {}
        self.tap_internal_key: bytes = b""
        # self.tap_merkle_root = # Not implemented

        self.unknown: Dict[bytes, bytes] = {}

    def set_null(self) -> None:
        """
        Clear all values in this PSBT input map.
        """
        self.non_witness_utxo = None
        self.witness_utxo = None
        self.partial_sigs.clear()
        self.sighash = 0
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()
        self.final_script_sig = b""
        self.final_script_witness = CTxInWitness()

        self.previous_txid = None
        self.output_index = None
        self.sequence = None
        self.required_time_locktime = None
        self.required_height_locktime = None

        self.tap_key_sig = b""
        self.tap_hd_keypaths = {}
        self.tap_internal_key = b""

        self.unknown.clear()

    def deserialize(self, f: Readable, psbt_version: int) -> None:
        """
        Deserialize a serialized PSBT input.

        :param f: A byte stream containing the serialized PSBT input
        """
        if psbt_version != 0 and psbt_version != 2:
            raise PSBTSerializationError(f"Unsupported version: {psbt_version}. Only versions 0 and 2 are supported")

        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            if key_type == 0:
                if self.non_witness_utxo:
                    raise PSBTSerializationError("Duplicate Key, input non witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("non witness utxo key is more than one byte type")
                self.non_witness_utxo = CTransaction()
                utxo_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.non_witness_utxo.deserialize(utxo_bytes)
                self.non_witness_utxo.rehash()

            elif key_type == 1:
                if self.witness_utxo:
                    raise PSBTSerializationError("Duplicate Key, input witness utxo already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witness utxo key is more than one byte type")
                self.witness_utxo = CTxOut()
                tx_out_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.witness_utxo.deserialize(tx_out_bytes)

            elif key_type == 2:
                if len(key) != 34 and len(key) != 66:
                    raise PSBTSerializationError("Size of key was not the expected size for the type partial signature pubkey")
                pubkey = key[1:]
                if pubkey in self.partial_sigs:
                    raise PSBTSerializationError("Duplicate key, input partial signature for pubkey already provided")

                sig = deser_string(f)
                self.partial_sigs[pubkey] = sig

            elif key_type == 3:
                if self.sighash > 0:
                    raise PSBTSerializationError("Duplicate key, input sighash type already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("sighash key is more than one byte type")
                sighash_bytes = deser_string(f)
                self.sighash = struct.unpack("<I", sighash_bytes)[0]

            elif key_type == 4:
                if len(self.redeem_script) != 0:
                    raise PSBTSerializationError("Duplicate key, input redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)

            elif key_type == 5:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError("Duplicate key, input witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)

            elif key_type == 6:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])

            elif key_type == 7:
                if len(self.final_script_sig) != 0:
                    raise PSBTSerializationError("Duplicate key, input final scriptSig already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptSig key is more than one byte type")
                self.final_script_sig = deser_string(f)

            elif key_type == 8:
                if not self.final_script_witness.is_null():
                    raise PSBTSerializationError("Duplicate key, input final scriptWitness already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("final scriptWitness key is more than one byte type")
                witness_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.final_script_witness.deserialize(witness_bytes)

            # key types 0x8 to 0x0d are defined in the standard, but left to the unknowns here

            elif key_type == 0x0e:
                if psbt_version == 0:
                    raise PSBTSerializationError("input previous txid key invalid for psbt version 0")
                if not self.previous_txid is None:
                    raise PSBTSerializationError("Duplicate key, input previous txid already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("input previous txid key must be exactly 1 byte long")

                self.previous_txid = deser_string(f)

                if len(self.previous_txid) != 32:
                    raise PSBTSerializationError("input previous txid value must be exactly 32 bytes")

            elif key_type == 0x0f:
                if psbt_version == 0:
                    raise PSBTSerializationError("input previous output index key invalid for psbt version 0")

                if self.output_index is not None:
                    raise PSBTSerializationError("Duplicate key, input previous output index already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("input previous output index key must be exactly 1 byte long")

                output_index_bytes = deser_string(f)

                if len(output_index_bytes) != 4:
                    raise PSBTSerializationError("Input previous output index must be exactly 4 bytes long")

                self.output_index = struct.unpack("<I", output_index_bytes)[0]

            elif key_type == 0x10:
                if psbt_version == 0:
                    raise PSBTSerializationError("input sequence number key invalid for psbt version 0")

                if self.sequence is not None:
                    raise PSBTSerializationError("Duplicate key, input sequence number already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("input sequence number key must be exactly 1 byte long")

                sequence_bytes = deser_string(f)

                if len(sequence_bytes) != 4:
                    raise PSBTSerializationError("Input sequence number must be exactly 4 bytes long")

                self.sequence = struct.unpack("<I", sequence_bytes)[0]

            elif key_type == 0x11:
                if psbt_version == 0:
                    raise PSBTSerializationError("input required time locktime key invalid for psbt version 0")

                if self.required_time_locktime is not None:
                    raise PSBTSerializationError("Duplicate key, input required time locktime already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("input required time locktime key must be exactly 1 byte long")

                required_time_locktime_bytes = deser_string(f)

                if len(required_time_locktime_bytes) != 4:
                    raise PSBTSerializationError("Input required time locktime must be exactly 1 bytes long")

                self.required_time_locktime = struct.unpack("<I", required_time_locktime_bytes)[0]

            elif key_type == 0x12:
                if psbt_version == 0:
                    raise PSBTSerializationError("input required height locktime key invalid for psbt version 0")

                if self.required_height_locktime is not None:
                    raise PSBTSerializationError("Duplicate key, input required height locktime already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("input required height locktime key must be exactly 1 byte long")

                required_height_locktime_bytes = deser_string(f)

                if len(required_height_locktime_bytes) != 4:
                    raise PSBTSerializationError("Input required height locktime must be exactly 4 bytes long")

                self.required_height_locktime = struct.unpack("<I", required_height_locktime_bytes)[0]

            elif key_type == 0x13:
                if len(self.tap_key_sig) != 0:
                    raise PSBTSerializationError("Duplicate key, input key path Schnorr signature already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input key path Schnorr signature key is more than one byte type")

                self.tap_key_sig = deser_string(f)

                if len(self.tap_key_sig) not in [64, 65]:
                    raise PSBTSerializationError("Input key path Schnorr signature must be 64 or 65 bytes long")

            # 0x14 and 0x15 are not implemented

            elif key_type == 0x16:
                DeserializeHDHashesKeypath(f, key, self.tap_hd_keypaths, [1 + 32])
            elif key_type == 0x17:
                if len(self.tap_internal_key) != 0:
                    raise PSBTSerializationError("Duplicate key, input taproot internal key already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Input taproot internal key's key is more than one byte type")

                self.tap_internal_key = deser_string(f)

                if len(self.tap_internal_key) != 32:
                    raise PSBTSerializationError("Input taproot internal key's value is not 32 bytes long")

            # 0x18 is not implemented

            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

        if psbt_version == 2:
            if self.previous_txid is None:
                raise PSBTSerializationError("Missing previous txid, but it is mandatory in PSBTv2")
            if self.output_index is None:
                raise PSBTSerializationError("Missing output index, but it is mandatory in PSBTv2")

    def serialize(self) -> bytes:
        """
        Serialize this PSBT input

        :returns: The serialized PSBT input
        """
        r = b""

        if self.non_witness_utxo:
            r += ser_string(b"\x00")
            tx = self.non_witness_utxo.serialize_with_witness()
            r += ser_string(tx)

        if self.witness_utxo:
            r += ser_string(b"\x01")
            tx = self.witness_utxo.serialize()
            r += ser_string(tx)

        if len(self.final_script_sig) == 0 and self.final_script_witness.is_null():
            for pubkey, sig in sorted(self.partial_sigs.items()):
                r += ser_string(b"\x02" + pubkey)
                r += ser_string(sig)

            if self.sighash > 0:
                r += ser_string(b"\x03")
                r += ser_string(struct.pack("<I", self.sighash))

            if len(self.redeem_script) != 0:
                r += ser_string(b"\x04")
                r += ser_string(self.redeem_script)

            if len(self.witness_script) != 0:
                r += ser_string(b"\x05")
                r += ser_string(self.witness_script)

            r += SerializeHDKeypath(self.hd_keypaths, b"\x06")

        if len(self.final_script_sig) != 0:
            r += ser_string(b"\x07")
            r += ser_string(self.final_script_sig)

        if not self.final_script_witness.is_null():
            r += ser_string(b"\x08")
            witstack = self.final_script_witness.serialize()
            r += ser_string(witstack)

        # serialize the unknown key types between 0x09 and 0x0d
        for key, value in sorted(self.unknown.items()):
            if 0x09 <= key[0] <= 0x0d:
                r += ser_string(key)
                r += ser_string(value)

        if self.previous_txid is not None:
            r += ser_string(b"\x0e")
            r += ser_string(self.previous_txid)

        if self.output_index is not None:
            r += ser_string(b"\x0f")
            r += ser_string(struct.pack("<I", self.output_index))

        if self.sequence is not None:
            r += ser_string(b"\x10")
            r += ser_string(struct.pack("<I", self.sequence))

        if self.required_time_locktime is not None:
            r += ser_string(b"\x11")
            r += ser_string(struct.pack("<I", self.required_time_locktime))

        if self.required_height_locktime is not None:
            r += ser_string(b"\x12")
            r += ser_string(struct.pack("<I", self.required_height_locktime))

        if len(self.tap_key_sig) != 0:
            r += ser_string(b"\x13")
            r += ser_string(self.tap_key_sig)

        # serialize the unknown key types 0x14 and 0x15
        for key, value in sorted(self.unknown.items()):
            if 0x14 <= key[0] <= 0x15:
                r += ser_string(key)
                r += ser_string(value)

        r += SerializeHDHashesKeypath(self.tap_hd_keypaths, b"\x16")

        if len(self.tap_internal_key) != 0:
            r += ser_string(b"\x17")
            r += ser_string(self.tap_internal_key)

        # serialize the unknown key types 0x18 and above
        for key, value in sorted(self.unknown.items()):
            if key[0] >= 0x18:
                r += ser_string(key)
                r += ser_string(value)

        r += b"\x00"

        return r

class PartiallySignedOutput:
    """
    An object for a PSBT output map.
    """

    def __init__(self) -> None:
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths: Dict[bytes, KeyOriginInfo] = {}

        # psbt2 extensions
        self.amount: Optional[int] = None
        self.script: Optional[bytes] = None

        # taproot
        self.tap_internal_key: bytes = b""
        # self.tap_tree = # Not implemented
        self.tap_hd_keypaths: Dict[bytes, Tuple[List[bytes], KeyOriginInfo]] = {}

        self.unknown: Dict[bytes, bytes] = {}

    def set_null(self) -> None:
        """
        Clear this PSBT output map
        """
        self.redeem_script = b""
        self.witness_script = b""
        self.hd_keypaths.clear()

        self.amount = None
        self.script = None

        self.tap_internal_key = b""
        self.tap_hd_keypaths = {}

        self.unknown.clear()

    def deserialize(self, f: Readable, psbt_version: int) -> None:
        """
        Deserialize a serialized PSBT output map

        :param f: A byte stream containing the serialized PSBT output
        """
        if psbt_version != 0 and psbt_version != 2:
            raise PSBTSerializationError(f"Unsupported version: {psbt_version}. Only versions 0 and 2 are supported")

        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            if key_type == 0:
                if len(self.redeem_script) != 0:
                    raise PSBTSerializationError("Duplicate key, output redeemScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output redeemScript key is more than one byte type")
                self.redeem_script = deser_string(f)

            elif key_type == 1:
                if len(self.witness_script) != 0:
                    raise PSBTSerializationError("Duplicate key, output witnessScript already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output witnessScript key is more than one byte type")
                self.witness_script = deser_string(f)

            elif key_type == 2:
                DeserializeHDKeypath(f, key, self.hd_keypaths, [34, 66])

            elif key_type == 3:
                if psbt_version == 0:
                    raise PSBTSerializationError("output amount key invalid for psbt version 0")

                if self.amount is not None:
                    raise PSBTSerializationError("Duplicate key, output amount already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output amount key must be exactly 1 byte long")

                amount_bytes = deser_string(f)

                if len(amount_bytes) != 8:
                    raise PSBTSerializationError("Output amount must be exactly 8 bytes long")

                self.amount = struct.unpack("<Q", amount_bytes)[0]

            elif key_type == 4:
                if psbt_version == 0:
                    raise PSBTSerializationError("output script key invalid for psbt version 0")

                if self.script is not None:
                    raise PSBTSerializationError("Duplicate key, output script already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output script key must be exactly 1 byte long")

                self.script = deser_string(f)

            elif key_type == 0x05:
                if len(self.tap_internal_key) != 0:
                    raise PSBTSerializationError("Duplicate key, output taproot internal key already provided")
                elif len(key) != 1:
                    raise PSBTSerializationError("Output taproot internal key's key is more than one byte type")

                self.tap_internal_key = deser_string(f)

                if len(self.tap_internal_key) != 32:
                    raise PSBTSerializationError("Output taproot internal key's value is not 32 bytes long")

            # 0x06 is not implemented

            elif key_type == 0x07:
                DeserializeHDHashesKeypath(f, key, self.tap_hd_keypaths, [1 + 32])

            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                value = deser_string(f)
                self.unknown[key] = value

        if psbt_version == 2:
            if self.amount is None:
                raise PSBTSerializationError("Missing amount, but it is mandatory in PSBTv2")
            if self.script is None:
                raise PSBTSerializationError("Missing script, but it is mandatory in PSBTv2")

    def serialize(self) -> bytes:
        """
        Serialize this PSBT output

        :returns: The serialized PSBT output
        """
        r = b""
        if len(self.redeem_script) != 0:
            r += ser_string(b"\x00")
            r += ser_string(self.redeem_script)

        if len(self.witness_script) != 0:
            r += ser_string(b"\x01")
            r += ser_string(self.witness_script)

        r += SerializeHDKeypath(self.hd_keypaths, b"\x02")

        if self.amount is not None:
            r += ser_string(b"\x03")
            r += ser_string(struct.pack("<Q", self.amount))

        if self.script is not None:
            r += ser_string(b"\x04")
            r += ser_string(self.script)

        if len(self.tap_internal_key) != 0:
            r += ser_string(b"\x05")
            r += ser_string(self.tap_internal_key)

        # key 0x06 is not implemented
        for key, value in sorted(self.unknown.items()):
            if key[0] == 0x06:
                r += ser_string(key)
                r += ser_string(value)

        if self.tap_hd_keypaths:
            r += SerializeHDHashesKeypath(self.tap_hd_keypaths, b"\x07")

        for key, value in sorted(self.unknown.items()):
            if key[0] >= 0x08:
                r += ser_string(key)
                r += ser_string(value)

        r += b"\x00"

        return r

class PSBT(object):
    """
    A class representing a PSBT
    """

    def __init__(self, tx: Optional[CTransaction] = None) -> None:
        """
        :param tx: A Bitcoin transaction that specifies the inputs and outputs to use
        """
        if tx:
            self.tx = tx
        else:
            self.tx = CTransaction()
        self.inputs: List[PartiallySignedInput] = []
        self.outputs: List[PartiallySignedOutput] = []
        self.unknown: Dict[bytes, bytes] = {}
        self.xpub: Dict[bytes, KeyOriginInfo] = {}
        self.version: Optional[int] = None

        # psbt2 extensions
        self.tx_version: Optional[int] = None
        self.fallback_locktime: Optional[int] = None
        self.input_count: Optional[int] = None
        self.output_count: Optional[int] = None
        self.tx_modifiable: Optional[int] = None

    def deserialize(self, psbt: str) -> None:
        """
        Deserialize a base 64 encoded PSBT.

        :param psbt: A base 64 PSBT.
        """
        psbt_bytes = base64.b64decode(psbt.strip())
        f = BufferedReader(BytesIO(psbt_bytes)) # type: ignore
        end = len(psbt_bytes)

        # Read the magic bytes
        magic = f.read(5)
        if magic != b"psbt\xff":
            raise PSBTSerializationError("invalid magic")

        # Read loop
        while True:
            # read the key
            try:
                key = deser_string(f)
            except Exception:
                break

            # Check for separator
            if len(key) == 0:
                break

            # First byte of key is the type
            key_type = struct.unpack("b", bytearray([key[0]]))[0]

            # Do stuff based on type
            if key_type == 0x00:
                # Checks for correctness
                if not self.tx.is_null:
                    raise PSBTSerializationError("Duplicate key, unsigned tx already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Global unsigned tx key is more than one byte type")

                # read in value
                tx_bytes = BufferedReader(BytesIO(deser_string(f))) # type: ignore
                self.tx.deserialize(tx_bytes)

                # Make sure that all scriptSigs and scriptWitnesses are empty
                for txin in self.tx.vin:
                    if len(txin.scriptSig) != 0 or not self.tx.wit.is_null():
                        raise PSBTSerializationError("Unsigned tx does not have empty scriptSigs and scriptWitnesses")
            elif key_type == 0x01:
                DeserializeHDKeypath(f, key, self.xpub, [79])
            elif key_type == 0x02:
                if self.tx_version is not None:
                    raise PSBTSerializationError("Duplicate key, tx version already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Tx version key is more than one byte type")

                self.tx_version = struct.unpack("<I", f.read(4))[0]
            elif key_type == 0x03:
                if self.fallback_locktime is not None:
                    raise PSBTSerializationError("Duplicate key, fallback locktime already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Fallback locktime key is more than one byte type")

                fallback_locktime_bytes = deser_string(f)
                if len(fallback_locktime_bytes) != 4:
                    raise PSBTSerializationError("Fallback locktime value must be exactly 4 bytes long")

                self.fallback_locktime = struct.unpack("<I", fallback_locktime_bytes)[0]
            elif key_type == 0x04:
                if self.input_count is not None:
                    raise PSBTSerializationError("Duplicate key, input count already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Input count key is more than one byte type")

                input_count_bytes = BufferedReader(BytesIO(deser_string(f)))
                self.input_count = deser_compact_size(input_count_bytes)
            elif key_type == 0x05:
                if self.output_count is not None:
                    raise PSBTSerializationError("Duplicate key, output count already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Output count key is more than one byte type")

                output_count_bytes = BufferedReader(BytesIO(deser_string(f)))
                self.output_count = deser_compact_size(output_count_bytes)
            elif key_type == 0x06:
                if self.tx_modifiable is not None:
                    raise PSBTSerializationError("Duplicate key, transaction modifiable flags already provided")
                elif len(key) > 1:
                    raise PSBTSerializationError("Transaction modifiable flags key is more than one byte type")

                tx_modifiable_bytes = deser_string(f)
                if len(tx_modifiable_bytes) != 1:
                    raise PSBTSerializationError("Transaction modifiable flags value must be exactly 1 byte long")

                self.tx_modifiable = tx_modifiable_bytes[0]
            elif key_type == 0xfb:
                if self.version is not None:
                    raise PSBTSerializationError("Duplicate key, psbt version already provided")
                elif len(key) != 4:
                    raise PSBTSerializationError("Psbt version must be exactly 4 bytes long")

                version_bytes = deser_string(f)

                if len(version_bytes) != 4:
                    raise PSBTSerializationError("Psbt version value must be exactly 4 bytes long")

                self.version = struct.unpack("<I", version_bytes)[0]

                if self.version != 0 and self.version != 1:
                    raise PSBTSerializationError("Only psbt versions 0 and 1 are supported")
            else:
                if key in self.unknown:
                    raise PSBTSerializationError("Duplicate key, key for unknown value already provided")
                unknown_bytes = deser_string(f)
                self.unknown[key] = unknown_bytes

        psbt_version: int = 0 if self.version is None else self.version

        if psbt_version == 0:
            # make sure that we got an unsigned tx
            if self.tx.is_null():
                raise PSBTSerializationError("No unsigned trasaction was provided")

            if self.tx_version is not None:
                raise PSBTSerializationError("Tx version is not allowed in PSBTv0")
            if self.fallback_locktime is not None:
                raise PSBTSerializationError("Fallback locktime is not allowed in PSBTv0")
            if self.input_count is not None:
                raise PSBTSerializationError("Input count is not allowed in PSBTv0")
            if self.output_count is not None:
                raise PSBTSerializationError("Output count is not allowed in PSBTv0")
            if self.tx_modifiable is not None:
                raise PSBTSerializationError("Transaction modifiable flags not allowed in PSBTv0")

        else:
            if not self.tx.is_null():
                raise PSBTSerializationError("Global transaction is not allowed in PSBTv2")

            if self.tx_version is None:
                raise PSBTSerializationError("Tx version is required in PSBTv2")
            if self.input_count is None:
                raise PSBTSerializationError("Input count is required in PSBTv2")
            if self.output_count is None:
                raise PSBTSerializationError("Output count is required in PSBTv2")

        # Read input data
        input_count = len(self.tx.vin) if psbt_version == 0 else self.input_count
        for input_idx in range(input_count):
            if f.tell() == end:
                break
            input = PartiallySignedInput()
            input.deserialize(f, psbt_version)
            self.inputs.append(input)

            prevout_hash = self.tx.vin[input_idx].prevout.hash if psbt_version == 0 else input.previous_txid

            if input.non_witness_utxo:
                input.non_witness_utxo.rehash()
                if input.non_witness_utxo.sha256 != prevout_hash:
                    raise PSBTSerializationError("Non-witness UTXO does not match outpoint hash")

        if psbt_version == 0 and (len(self.inputs) != input_count):
            raise PSBTSerializationError("Inputs provided do not match the number of inputs in transaction")

        # Read output data
        output_count = len(self.tx.vout) if psbt_version == 0 else self.output_count
        for _ in range(output_count):
            if f.tell() == end:
                break
            output = PartiallySignedOutput()
            output.deserialize(f, psbt_version)
            self.outputs.append(output)

        if len(self.outputs) != output_count:
            raise PSBTSerializationError(f"Outputs provided do not match the number of outputs in transaction: {psbt_version} {len(self.outputs)} {output_count}")

    def serialize(self) -> str:
        """
        Serialize the PSBT as a base 64 encoded string.

        :returns: The base 64 encoded string.
        """
        r = b""

        # magic bytes
        r += b"psbt\xff"

        # unsigned tx flag
        r += b"\x01\x00"

        # write serialized tx
        tx = self.tx.serialize_with_witness()
        r += ser_compact_size(len(tx))
        r += tx

        # write xpubs
        r += SerializeHDKeypath(self.xpub, b"\x01")

        # tx version
        if self.tx_version is not None:
            r += b"\x01\x02"
            r += ser_string(struct.pack("<I", self.tx_version))

        # tx fallback locktime
        if self.fallback_locktime is not None:
            r += b"\x01\x03"
            r += ser_string(struct.pack("<I", self.fallback_locktime))

        # input count
        if self.input_count is not None:
            r += b"\x01\x04"
            r += ser_string(ser_compact_size(self.input_count))

        # output count
        if self.output_count is not None:
            r += b"\x01\x05"
            r += ser_string(ser_compact_size(self.output_count))

        # transaction modifiable flags
        if self.tx_modifiable is not None:
            r += b"\x01\x06"
            r += ser_string(struct.pack("<B", self.tx_modifiable))

        # psbt version
        if self.version is not None:
            r += b"\x01\xfb"
            r += ser_string(struct.pack("<I", self.version))

        # unknowns
        for key, value in sorted(self.unknown.items()):
            r += ser_string(key)
            r += ser_string(value)

        # separator
        r += b"\x00"

        # inputs
        for input in self.inputs:
            r += input.serialize()

        # outputs
        for output in self.outputs:
            r += output.serialize()

        # return hex string
        return base64.b64encode(r).decode()

    def to_psbt_v2(self) -> None:
        """
        Converts a valid psbt from version 0 to version 2.
        """

        if not (self.version is None or self.version == 0):
            raise ValueError("Can only convert from version 0 to version 2")

        self.version = 2

        tx = self.tx

        self.tx = CTransaction()

        self.tx_version = tx.nVersion

        self.fallback_locktime = tx.nLockTime

        self.input_count = len(tx.vin)
        self.output_count = len(tx.vout)

        for input_idx in range(len(tx.vin)):
            self.inputs[input_idx].previous_txid = ser_uint256(tx.vin[input_idx].prevout.hash)
            self.inputs[input_idx].output_index = tx.vin[input_idx].prevout.n
            self.inputs[input_idx].sequence = tx.vin[input_idx].nSequence

            if tx.nLockTime >= 500_000_000:
                self.inputs[input_idx].required_time_locktime = tx.nLockTime
            else:
                self.inputs[input_idx].required_height_locktime = tx.nLockTime

        for output_idx in range(len(tx.vout)):
            self.outputs[output_idx].amount = tx.vout[output_idx].nValue
            self.outputs[output_idx].script = tx.vout[output_idx].scriptPubKey
