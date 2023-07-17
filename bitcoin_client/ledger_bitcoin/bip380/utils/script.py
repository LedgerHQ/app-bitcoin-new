# Copyright (c) 2015-2020 The Bitcoin Core developers
# Copyright (c) 2021 Antoine Poinsot
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
"""Script utilities

This file was taken from Bitcoin Core test framework, and was previously
modified from python-bitcoinlib.
"""
import struct

from .bignum import bn2vch


OPCODE_NAMES = {}


class CScriptOp(int):
    """A single script opcode"""

    __slots__ = ()

    @staticmethod
    def encode_op_pushdata(d):
        """Encode a PUSHDATA op, returning bytes"""
        if len(d) < 0x4C:
            return b"" + bytes([len(d)]) + d  # OP_PUSHDATA
        elif len(d) <= 0xFF:
            return b"\x4c" + bytes([len(d)]) + d  # OP_PUSHDATA1
        elif len(d) <= 0xFFFF:
            return b"\x4d" + struct.pack(b"<H", len(d)) + d  # OP_PUSHDATA2
        elif len(d) <= 0xFFFFFFFF:
            return b"\x4e" + struct.pack(b"<I", len(d)) + d  # OP_PUSHDATA4
        else:
            raise ValueError("Data too long to encode in a PUSHDATA op")

    @staticmethod
    def encode_op_n(n):
        """Encode a small integer op, returning an opcode"""
        if not (0 <= n <= 16):
            raise ValueError("Integer must be in range 0 <= n <= 16, got %d" % n)

        if n == 0:
            return OP_0
        else:
            return CScriptOp(OP_1 + n - 1)

    def decode_op_n(self):
        """Decode a small integer opcode, returning an integer"""
        if self == OP_0:
            return 0

        if not (self == OP_0 or OP_1 <= self <= OP_16):
            raise ValueError("op %r is not an OP_N" % self)

        return int(self - OP_1 + 1)

    def is_small_int(self):
        """Return true if the op pushes a small integer to the stack"""
        if 0x51 <= self <= 0x60 or self == 0:
            return True
        else:
            return False

    def __str__(self):
        return repr(self)

    def __repr__(self):
        if self in OPCODE_NAMES:
            return OPCODE_NAMES[self]
        else:
            return "CScriptOp(0x%x)" % self


# push value
OP_0 = CScriptOp(0x00)
OP_FALSE = OP_0
OP_PUSHDATA1 = CScriptOp(0x4C)
OP_PUSHDATA2 = CScriptOp(0x4D)
OP_PUSHDATA4 = CScriptOp(0x4E)
OP_1NEGATE = CScriptOp(0x4F)
OP_RESERVED = CScriptOp(0x50)
OP_1 = CScriptOp(0x51)
OP_TRUE = OP_1
OP_2 = CScriptOp(0x52)
OP_3 = CScriptOp(0x53)
OP_4 = CScriptOp(0x54)
OP_5 = CScriptOp(0x55)
OP_6 = CScriptOp(0x56)
OP_7 = CScriptOp(0x57)
OP_8 = CScriptOp(0x58)
OP_9 = CScriptOp(0x59)
OP_10 = CScriptOp(0x5A)
OP_11 = CScriptOp(0x5B)
OP_12 = CScriptOp(0x5C)
OP_13 = CScriptOp(0x5D)
OP_14 = CScriptOp(0x5E)
OP_15 = CScriptOp(0x5F)
OP_16 = CScriptOp(0x60)

# control
OP_IF = CScriptOp(0x63)
OP_NOTIF = CScriptOp(0x64)
OP_ELSE = CScriptOp(0x67)
OP_ENDIF = CScriptOp(0x68)
OP_VERIFY = CScriptOp(0x69)

# stack ops
OP_TOALTSTACK = CScriptOp(0x6B)
OP_FROMALTSTACK = CScriptOp(0x6C)
OP_IFDUP = CScriptOp(0x73)
OP_DUP = CScriptOp(0x76)
OP_SWAP = CScriptOp(0x7C)
OP_SIZE = CScriptOp(0x82)

# bit logic
OP_EQUAL = CScriptOp(0x87)
OP_EQUALVERIFY = CScriptOp(0x88)

# numeric
OP_NOT = CScriptOp(0x91)
OP_0NOTEQUAL = CScriptOp(0x92)

OP_ADD = CScriptOp(0x93)

OP_BOOLAND = CScriptOp(0x9A)
OP_BOOLOR = CScriptOp(0x9B)

# crypto
OP_RIPEMD160 = CScriptOp(0xA6)
OP_SHA256 = CScriptOp(0xA8)
OP_HASH160 = CScriptOp(0xA9)
OP_HASH256 = CScriptOp(0xAA)
OP_CHECKSIG = CScriptOp(0xAC)
OP_CHECKSIGVERIFY = CScriptOp(0xAD)
OP_CHECKMULTISIG = CScriptOp(0xAE)
OP_CHECKMULTISIGVERIFY = CScriptOp(0xAF)

# expansion
OP_CHECKLOCKTIMEVERIFY = CScriptOp(0xB1)
OP_CHECKSEQUENCEVERIFY = CScriptOp(0xB2)

OP_INVALIDOPCODE = CScriptOp(0xFF)

OPCODE_NAMES.update(
    {
        OP_0: "OP_0",
        OP_PUSHDATA1: "OP_PUSHDATA1",
        OP_PUSHDATA2: "OP_PUSHDATA2",
        OP_PUSHDATA4: "OP_PUSHDATA4",
        OP_1NEGATE: "OP_1NEGATE",
        OP_RESERVED: "OP_RESERVED",
        OP_1: "OP_1",
        OP_2: "OP_2",
        OP_3: "OP_3",
        OP_4: "OP_4",
        OP_5: "OP_5",
        OP_6: "OP_6",
        OP_7: "OP_7",
        OP_8: "OP_8",
        OP_9: "OP_9",
        OP_10: "OP_10",
        OP_11: "OP_11",
        OP_12: "OP_12",
        OP_13: "OP_13",
        OP_14: "OP_14",
        OP_15: "OP_15",
        OP_16: "OP_16",
        OP_IF: "OP_IF",
        OP_NOTIF: "OP_NOTIF",
        OP_ELSE: "OP_ELSE",
        OP_ENDIF: "OP_ENDIF",
        OP_VERIFY: "OP_VERIFY",
        OP_TOALTSTACK: "OP_TOALTSTACK",
        OP_FROMALTSTACK: "OP_FROMALTSTACK",
        OP_IFDUP: "OP_IFDUP",
        OP_DUP: "OP_DUP",
        OP_SWAP: "OP_SWAP",
        OP_SIZE: "OP_SIZE",
        OP_EQUAL: "OP_EQUAL",
        OP_EQUALVERIFY: "OP_EQUALVERIFY",
        OP_NOT: "OP_NOT",
        OP_0NOTEQUAL: "OP_0NOTEQUAL",
        OP_ADD: "OP_ADD",
        OP_BOOLAND: "OP_BOOLAND",
        OP_BOOLOR: "OP_BOOLOR",
        OP_RIPEMD160: "OP_RIPEMD160",
        OP_SHA256: "OP_SHA256",
        OP_HASH160: "OP_HASH160",
        OP_HASH256: "OP_HASH256",
        OP_CHECKSIG: "OP_CHECKSIG",
        OP_CHECKSIGVERIFY: "OP_CHECKSIGVERIFY",
        OP_CHECKMULTISIG: "OP_CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY: "OP_CHECKMULTISIGVERIFY",
        OP_CHECKLOCKTIMEVERIFY: "OP_CHECKLOCKTIMEVERIFY",
        OP_CHECKSEQUENCEVERIFY: "OP_CHECKSEQUENCEVERIFY",
        OP_INVALIDOPCODE: "OP_INVALIDOPCODE",
    }
)


class ScriptNumError(ValueError):
    def __init__(self, message):
        self.message = message


def read_script_number(data):
    """Read a Script number from {data} bytes"""
    size = len(data)
    if size > 4:
        raise ScriptNumError("Too large push")

    if size == 0:
        return 0

    # We always check for minimal encoding
    if (data[size - 1] & 0x7f) == 0:
        if size == 1 or (data[size - 2] & 0x80) == 0:
            raise ScriptNumError("Non minimal encoding")

    res = int.from_bytes(data, byteorder="little")

    # Remove the sign bit if set, and negate the result
    if data[size - 1] & 0x80:
        return -(res & ~(0x80 << (size - 1)))
    return res


class CScriptInvalidError(Exception):
    """Base class for CScript exceptions"""

    pass


class CScriptTruncatedPushDataError(CScriptInvalidError):
    """Invalid pushdata due to truncation"""

    def __init__(self, msg, data):
        self.data = data
        super(CScriptTruncatedPushDataError, self).__init__(msg)


# This is used, eg, for blockchain heights in coinbase scripts (bip34)
class CScriptNum:
    __slots__ = ("value",)

    def __init__(self, d=0):
        self.value = d

    @staticmethod
    def encode(obj):
        r = bytearray(0)
        if obj.value == 0:
            return bytes(r)
        neg = obj.value < 0
        absvalue = -obj.value if neg else obj.value
        while absvalue:
            r.append(absvalue & 0xFF)
            absvalue >>= 8
        if r[-1] & 0x80:
            r.append(0x80 if neg else 0)
        elif neg:
            r[-1] |= 0x80
        return bytes([len(r)]) + r

    @staticmethod
    def decode(vch):
        result = 0
        # We assume valid push_size and minimal encoding
        value = vch[1:]
        if len(value) == 0:
            return result
        for i, byte in enumerate(value):
            result |= int(byte) << 8 * i
        if value[-1] >= 0x80:
            # Mask for all but the highest result bit
            num_mask = (2 ** (len(value) * 8) - 1) >> 1
            result &= num_mask
            result *= -1
        return result


class CScript(bytes):
    """Serialized script

    A bytes subclass, so you can use this directly whenever bytes are accepted.
    Note that this means that indexing does *not* work - you'll get an index by
    byte rather than opcode. This format was chosen for efficiency so that the
    general case would not require creating a lot of little CScriptOP objects.

    iter(script) however does iterate by opcode.
    """

    __slots__ = ()

    @classmethod
    def __coerce_instance(cls, other):
        # Coerce other into bytes
        if isinstance(other, CScriptOp):
            other = bytes([other])
        elif isinstance(other, CScriptNum):
            if other.value == 0:
                other = bytes([CScriptOp(OP_0)])
            else:
                other = CScriptNum.encode(other)
        elif isinstance(other, int):
            if 0 <= other <= 16:
                other = bytes([CScriptOp.encode_op_n(other)])
            elif other == -1:
                other = bytes([OP_1NEGATE])
            else:
                other = CScriptOp.encode_op_pushdata(bn2vch(other))
        elif isinstance(other, (bytes, bytearray)):
            other = CScriptOp.encode_op_pushdata(other)
        return other

    def __add__(self, other):
        # Do the coercion outside of the try block so that errors in it are
        # noticed.
        other = self.__coerce_instance(other)

        try:
            # bytes.__add__ always returns bytes instances unfortunately
            return CScript(super(CScript, self).__add__(other))
        except TypeError:
            raise TypeError("Can not add a %r instance to a CScript" % other.__class__)

    def join(self, iterable):
        # join makes no sense for a CScript()
        raise NotImplementedError

    def __new__(cls, value=b""):
        if isinstance(value, bytes) or isinstance(value, bytearray):
            return super(CScript, cls).__new__(cls, value)
        else:

            def coerce_iterable(iterable):
                for instance in iterable:
                    yield cls.__coerce_instance(instance)

            # Annoyingly on both python2 and python3 bytes.join() always
            # returns a bytes instance even when subclassed.
            return super(CScript, cls).__new__(cls, b"".join(coerce_iterable(value)))

    def raw_iter(self):
        """Raw iteration

        Yields tuples of (opcode, data, sop_idx) so that the different possible
        PUSHDATA encodings can be accurately distinguished, as well as
        determining the exact opcode byte indexes. (sop_idx)
        """
        i = 0
        while i < len(self):
            sop_idx = i
            opcode = self[i]
            i += 1

            if opcode > OP_PUSHDATA4:
                yield (opcode, None, sop_idx)
            else:
                datasize = None
                pushdata_type = None
                if opcode < OP_PUSHDATA1:
                    pushdata_type = "PUSHDATA(%d)" % opcode
                    datasize = opcode

                elif opcode == OP_PUSHDATA1:
                    pushdata_type = "PUSHDATA1"
                    if i >= len(self):
                        raise CScriptInvalidError("PUSHDATA1: missing data length")
                    datasize = self[i]
                    i += 1

                elif opcode == OP_PUSHDATA2:
                    pushdata_type = "PUSHDATA2"
                    if i + 1 >= len(self):
                        raise CScriptInvalidError("PUSHDATA2: missing data length")
                    datasize = self[i] + (self[i + 1] << 8)
                    i += 2

                elif opcode == OP_PUSHDATA4:
                    pushdata_type = "PUSHDATA4"
                    if i + 3 >= len(self):
                        raise CScriptInvalidError("PUSHDATA4: missing data length")
                    datasize = (
                        self[i]
                        + (self[i + 1] << 8)
                        + (self[i + 2] << 16)
                        + (self[i + 3] << 24)
                    )
                    i += 4

                else:
                    assert False  # shouldn't happen

                data = bytes(self[i: i + datasize])

                # Check for truncation
                if len(data) < datasize:
                    raise CScriptTruncatedPushDataError(
                        "%s: truncated data" % pushdata_type, data
                    )

                i += datasize

                yield (opcode, data, sop_idx)

    def __iter__(self):
        """'Cooked' iteration

        Returns either a CScriptOP instance, an integer, or bytes, as
        appropriate.

        See raw_iter() if you need to distinguish the different possible
        PUSHDATA encodings.
        """
        for (opcode, data, sop_idx) in self.raw_iter():
            if data is not None:
                yield data
            else:
                opcode = CScriptOp(opcode)

                if opcode.is_small_int():
                    yield opcode.decode_op_n()
                else:
                    yield CScriptOp(opcode)

    def __repr__(self):
        def _repr(o):
            if isinstance(o, bytes):
                return "x('%s')" % o.hex()
            else:
                return repr(o)

        ops = []
        i = iter(self)
        while True:
            op = None
            try:
                op = _repr(next(i))
            except CScriptTruncatedPushDataError as err:
                op = "%s...<ERROR: %s>" % (_repr(err.data), err)
                break
            except CScriptInvalidError as err:
                op = "<ERROR: %s>" % err
                break
            except StopIteration:
                break
            finally:
                if op is not None:
                    ops.append(op)

        return "CScript([%s])" % ", ".join(ops)

    def GetSigOpCount(self, fAccurate):
        """Get the SigOp count.

        fAccurate - Accurately count CHECKMULTISIG, see BIP16 for details.

        Note that this is consensus-critical.
        """
        n = 0
        lastOpcode = OP_INVALIDOPCODE
        for (opcode, data, sop_idx) in self.raw_iter():
            if opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                n += 1
            elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                if fAccurate and (OP_1 <= lastOpcode <= OP_16):
                    n += opcode.decode_op_n()
                else:
                    n += 20
            lastOpcode = opcode
        return n
