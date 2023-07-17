"""
Miniscript AST elements.

Each element correspond to a Bitcoin Script fragment, and has various type properties.
See the Miniscript website for the specification of the type system: https://bitcoin.sipa.be/miniscript/.
"""

import copy
from ...bip380.miniscript import parsing

from ...bip380.key import DescriptorKey
from ...bip380.utils.hashes import hash160
from ...bip380.utils.script import (
    CScript,
    OP_1,
    OP_0,
    OP_ADD,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_IFDUP,
    OP_IF,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_HASH160,
    OP_HASH256,
    OP_NOTIF,
    OP_RIPEMD160,
    OP_SHA256,
    OP_SIZE,
    OP_SWAP,
    OP_TOALTSTACK,
    OP_VERIFY,
    OP_0NOTEQUAL,
)

from .errors import MiniscriptNodeCreationError
from .property import Property
from .satisfaction import ExecutionInfo, Satisfaction


# Threshold for nLockTime: below this value it is interpreted as block number,
# otherwise as UNIX timestamp.
LOCKTIME_THRESHOLD = 500000000  # Tue Nov  5 00:53:20 1985 UTC

# If CTxIn::nSequence encodes a relative lock-time and this flag
# is set, the relative lock-time has units of 512 seconds,
# otherwise it specifies blocks with a granularity of 1.
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22


class Node:
    """A Miniscript fragment."""

    # The fragment's type and properties
    p = None
    # List of all sub fragments
    subs = []
    # A list of Script elements, a CScript is created all at once in the script() method.
    _script = []
    # Whether any satisfaction for this fragment require a signature
    needs_sig = None
    # Whether any dissatisfaction for this fragment requires a signature
    is_forced = None
    # Whether this fragment has a unique unconditional satisfaction, and all conditional
    # ones require a signature.
    is_expressive = None
    # Whether for any possible way to satisfy this fragment (may be none), a
    # non-malleable satisfaction exists.
    is_nonmalleable = None
    # Whether this node or any of its subs contains an absolute heightlock
    abs_heightlocks = None
    # Whether this node or any of its subs contains a relative heightlock
    rel_heightlocks = None
    # Whether this node or any of its subs contains an absolute timelock
    abs_timelocks = None
    # Whether this node or any of its subs contains a relative timelock
    rel_timelocks = None
    # Whether this node does not contain a mix of timelock or heightlock of different types.
    # That is, not (abs_heightlocks and rel_heightlocks or abs_timelocks and abs_timelocks)
    no_timelock_mix = None
    # Information about this Miniscript execution (satisfaction cost, etc..)
    exec_info = None

    def __init__(self, *args, **kwargs):
        # Needs to be implemented by derived classes.
        raise NotImplementedError

    def from_str(ms_str):
        """Parse a Miniscript fragment from its string representation."""
        assert isinstance(ms_str, str)
        return parsing.miniscript_from_str(ms_str)

    def from_script(script, pkh_preimages={}):
        """Decode a Miniscript fragment from its Script representation."""
        assert isinstance(script, CScript)
        return parsing.miniscript_from_script(script, pkh_preimages)

    # TODO: have something like BuildScript from Core and get rid of the _script member.
    @property
    def script(self):
        return CScript(self._script)

    @property
    def keys(self):
        """Get the list of all keys from this Miniscript, in order of apparition."""
        # Overriden by fragments that actually have keys.
        return [key for sub in self.subs for key in sub.keys]

    def satisfy(self, sat_material):
        """Get the witness of the smallest non-malleable satisfaction for this fragment,
        if one exists.

        :param sat_material: a SatisfactionMaterial containing available data to satisfy
                             challenges.
        """
        sat = self.satisfaction(sat_material)
        if not sat.has_sig:
            return None
        return sat.witness

    def satisfaction(self, sat_material):
        """Get the satisfaction for this fragment.

        :param sat_material: a SatisfactionMaterial containing available data to satisfy
                             challenges.
        """
        # Needs to be implemented by derived classes.
        raise NotImplementedError

    def dissatisfaction(self):
        """Get the dissatisfaction for this fragment."""
        # Needs to be implemented by derived classes.
        raise NotImplementedError


class Just0(Node):
    def __init__(self):

        self._script = [OP_0]

        self.p = Property("Bzud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True
        self.abs_heightlocks = False
        self.rel_heightlocks = False
        self.abs_timelocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(0, 0, None, 0)

    def satisfaction(self, sat_material):
        return Satisfaction.unavailable()

    def dissatisfaction(self):
        return Satisfaction(witness=[])

    def __repr__(self):
        return "0"


class Just1(Node):
    def __init__(self):

        self._script = [OP_1]

        self.p = Property("Bzu")
        self.needs_sig = False
        self.is_forced = True  # No dissat
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True  # FIXME: how comes? Standardness rules?
        self.abs_heightlocks = False
        self.rel_heightlocks = False
        self.abs_timelocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(0, 0, 0, None)

    def satisfaction(self, sat_material):
        return Satisfaction(witness=[])

    def dissatisfaction(self):
        return Satisfaction.unavailable()

    def __repr__(self):
        return "1"


class PkNode(Node):
    """A virtual class for nodes containing a single public key.

    Should not be instanced directly, use Pk() or Pkh().
    """

    def __init__(self, pubkey):

        if isinstance(pubkey, bytes) or isinstance(pubkey, str):
            self.pubkey = DescriptorKey(pubkey)
        elif isinstance(pubkey, DescriptorKey):
            self.pubkey = pubkey
        else:
            raise MiniscriptNodeCreationError("Invalid public key")

        self.needs_sig = True  # FIXME: think about having it in 'c:' instead
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True
        self.abs_heightlocks = False
        self.rel_heightlocks = False
        self.abs_timelocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True

    @property
    def keys(self):
        return [self.pubkey]


class Pk(PkNode):
    def __init__(self, pubkey):
        PkNode.__init__(self, pubkey)

        self.p = Property("Konud")
        self.exec_info = ExecutionInfo(0, 0, 0, 0)

    @property
    def _script(self):
        return [self.pubkey.bytes()]

    def satisfaction(self, sat_material):
        sig = sat_material.signatures.get(self.pubkey.bytes())
        if sig is None:
            return Satisfaction.unavailable()
        return Satisfaction([sig], has_sig=True)

    def dissatisfaction(self):
        return Satisfaction(witness=[b""])

    def __repr__(self):
        return f"pk_k({self.pubkey})"


class Pkh(PkNode):
    # FIXME: should we support a hash here, like rust-bitcoin? I don't think it's safe.
    def __init__(self, pubkey):
        PkNode.__init__(self, pubkey)

        self.p = Property("Knud")
        self.exec_info = ExecutionInfo(3, 0, 1, 1)

    @property
    def _script(self):
        return [OP_DUP, OP_HASH160, self.pk_hash(), OP_EQUALVERIFY]

    def satisfaction(self, sat_material):
        sig = sat_material.signatures.get(self.pubkey.bytes())
        if sig is None:
            return Satisfaction.unavailable()
        return Satisfaction(witness=[sig, self.pubkey.bytes()], has_sig=True)

    def dissatisfaction(self):
        return Satisfaction(witness=[b"", self.pubkey.bytes()])

    def __repr__(self):
        return f"pk_h({self.pubkey})"

    def pk_hash(self):
        assert isinstance(self.pubkey, DescriptorKey)
        return hash160(self.pubkey.bytes())


class Older(Node):
    def __init__(self, value):
        assert value > 0 and value < 2 ** 31

        self.value = value
        self._script = [self.value, OP_CHECKSEQUENCEVERIFY]

        self.p = Property("Bz")
        self.needs_sig = False
        self.is_forced = True
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True
        self.rel_timelocks = bool(value & SEQUENCE_LOCKTIME_TYPE_FLAG)
        self.rel_heightlocks = not self.rel_timelocks
        self.abs_heightlocks = False
        self.abs_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(1, 0, 0, None)

    def satisfaction(self, sat_material):
        if sat_material.max_sequence < self.value:
            return Satisfaction.unavailable()
        return Satisfaction(witness=[])

    def dissatisfaction(self):
        return Satisfaction.unavailable()

    def __repr__(self):
        return f"older({self.value})"


class After(Node):
    def __init__(self, value):
        assert value > 0 and value < 2 ** 31

        self.value = value
        self._script = [self.value, OP_CHECKLOCKTIMEVERIFY]

        self.p = Property("Bz")
        self.needs_sig = False
        self.is_forced = True
        self.is_expressive = False  # No dissat
        self.is_nonmalleable = True
        self.abs_heightlocks = value < LOCKTIME_THRESHOLD
        self.abs_timelocks = not self.abs_heightlocks
        self.rel_heightlocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(1, 0, 0, None)

    def satisfaction(self, sat_material):
        if sat_material.max_lock_time < self.value:
            return Satisfaction.unavailable()
        return Satisfaction(witness=[])

    def dissatisfaction(self):
        return Satisfaction.unavailable()

    def __repr__(self):
        return f"after({self.value})"


class HashNode(Node):
    """A virtual class for fragments with hashlock semantics.

    Should not be instanced directly, use concrete fragments instead.
    """

    def __init__(self, digest, hash_op):
        assert isinstance(digest, bytes)  # TODO: real errors

        self.digest = digest
        self._script = [OP_SIZE, 32, OP_EQUALVERIFY, hash_op, digest, OP_EQUAL]

        self.p = Property("Bonud")
        self.needs_sig = False
        self.is_forced = False
        self.is_expressive = False
        self.is_nonmalleable = True
        self.abs_heightlocks = False
        self.rel_heightlocks = False
        self.abs_timelocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(4, 0, 1, None)

    def satisfaction(self, sat_material):
        preimage = sat_material.preimages.get(self.digest)
        if preimage is None:
            return Satisfaction.unavailable()
        return Satisfaction(witness=[preimage])

    def dissatisfaction(self):
        return Satisfaction.unavailable()
        return Satisfaction(witness=[b""])


class Sha256(HashNode):
    def __init__(self, digest):
        assert len(digest) == 32  # TODO: real errors
        HashNode.__init__(self, digest, OP_SHA256)

    def __repr__(self):
        return f"sha256({self.digest.hex()})"


class Hash256(HashNode):
    def __init__(self, digest):
        assert len(digest) == 32  # TODO: real errors
        HashNode.__init__(self, digest, OP_HASH256)

    def __repr__(self):
        return f"hash256({self.digest.hex()})"


class Ripemd160(HashNode):
    def __init__(self, digest):
        assert len(digest) == 20  # TODO: real errors
        HashNode.__init__(self, digest, OP_RIPEMD160)

    def __repr__(self):
        return f"ripemd160({self.digest.hex()})"


class Hash160(HashNode):
    def __init__(self, digest):
        assert len(digest) == 20  # TODO: real errors
        HashNode.__init__(self, digest, OP_HASH160)

    def __repr__(self):
        return f"hash160({self.digest.hex()})"


class Multi(Node):
    def __init__(self, k, keys):
        assert 1 <= k <= len(keys)
        assert all(isinstance(k, DescriptorKey) for k in keys)

        self.k = k
        self.pubkeys = keys

        self.p = Property("Bndu")
        self.needs_sig = True
        self.is_forced = False
        self.is_expressive = True
        self.is_nonmalleable = True
        self.abs_heightlocks = False
        self.rel_heightlocks = False
        self.abs_timelocks = False
        self.rel_timelocks = False
        self.no_timelock_mix = True
        self.exec_info = ExecutionInfo(1, len(keys), 1 + k, 1 + k)

    @property
    def keys(self):
        return self.pubkeys

    @property
    def _script(self):
        return [
            self.k,
            *[k.bytes() for k in self.keys],
            len(self.keys),
            OP_CHECKMULTISIG,
        ]

    def satisfaction(self, sat_material):
        sigs = []
        for key in self.keys:
            sig = sat_material.signatures.get(key.bytes())
            if sig is not None:
                assert isinstance(sig, bytes)
                sigs.append(sig)
            if len(sigs) == self.k:
                break
        if len(sigs) < self.k:
            return Satisfaction.unavailable()
        return Satisfaction(witness=[b""] + sigs, has_sig=True)

    def dissatisfaction(self):
        return Satisfaction(witness=[b""] * (self.k + 1))

    def __repr__(self):
        return f"multi({','.join([str(self.k)] + [str(k) for k in self.keys])})"


class AndV(Node):
    def __init__(self, sub_x, sub_y):
        assert sub_x.p.V
        assert sub_y.p.has_any("BKV")

        self.subs = [sub_x, sub_y]

        self.p = Property(
            sub_y.p.type()
            + ("z" if sub_x.p.z and sub_y.p.z else "")
            + ("o" if sub_x.p.z and sub_y.p.o or sub_x.p.o and sub_y.p.z else "")
            + ("n" if sub_x.p.n or sub_x.p.z and sub_y.p.n else "")
            + ("u" if sub_y.p.u else "")
        )
        self.needs_sig = any(sub.needs_sig for sub in self.subs)
        self.is_forced = any(sub.needs_sig for sub in self.subs)
        self.is_expressive = False  # Not 'd'
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs)
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = not (
            self.abs_heightlocks
            and self.abs_timelocks
            or self.rel_heightlocks
            and self.rel_timelocks
        )

    @property
    def _script(self):
        return sum((sub._script for sub in self.subs), start=[])

    @property
    def exec_info(self):
        exec_info = ExecutionInfo.from_concat(
            self.subs[0].exec_info, self.subs[1].exec_info
        )
        exec_info.set_undissatisfiable()  # it's V.
        return exec_info

    def satisfaction(self, sat_material):
        return Satisfaction.from_concat(sat_material, *self.subs)

    def dissatisfaction(self):
        return Satisfaction.unavailable()  # it's V.

    def __repr__(self):
        return f"and_v({','.join(map(str, self.subs))})"


class AndB(Node):
    def __init__(self, sub_x, sub_y):
        assert sub_x.p.B and sub_y.p.W

        self.subs = [sub_x, sub_y]

        self.p = Property(
            "Bu"
            + ("z" if sub_x.p.z and sub_y.p.z else "")
            + ("o" if sub_x.p.z and sub_y.p.o or sub_x.p.o and sub_y.p.z else "")
            + ("n" if sub_x.p.n or sub_x.p.z and sub_y.p.n else "")
            + ("d" if sub_x.p.d and sub_y.p.d else "")
            + ("u" if sub_y.p.u else "")
        )
        self.needs_sig = any(sub.needs_sig for sub in self.subs)
        self.is_forced = (
            sub_x.is_forced
            and sub_y.is_forced
            or any(sub.is_forced and sub.needs_sig for sub in self.subs)
        )
        self.is_expressive = all(sub.is_forced and sub.needs_sig for sub in self.subs)
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs)
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = not (
            self.abs_heightlocks
            and self.abs_timelocks
            or self.rel_heightlocks
            and self.rel_timelocks
        )

    @property
    def _script(self):
        return sum((sub._script for sub in self.subs), start=[]) + [OP_BOOLAND]

    @property
    def exec_info(self):
        return ExecutionInfo.from_concat(
            self.subs[0].exec_info, self.subs[1].exec_info, ops_count=1
        )

    def satisfaction(self, sat_material):
        return Satisfaction.from_concat(sat_material, self.subs[0], self.subs[1])

    def dissatisfaction(self):
        return self.subs[1].dissatisfaction() + self.subs[0].dissatisfaction()

    def __repr__(self):
        return f"and_b({','.join(map(str, self.subs))})"


class OrB(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bd")
        assert sub_z.p.has_all("Wd")

        self.subs = [sub_x, sub_z]

        self.p = Property(
            "Bdu"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.z and sub_z.p.o or sub_x.p.o and sub_z.p.z else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = False  # Both subs are 'd'
        self.is_expressive = all(sub.is_expressive for sub in self.subs)
        self.is_nonmalleable = all(
            sub.is_nonmalleable and sub.is_expressive for sub in self.subs
        ) and any(sub.needs_sig for sub in self.subs)
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = all(sub.no_timelock_mix for sub in self.subs)

    @property
    def _script(self):
        return sum((sub._script for sub in self.subs), start=[]) + [OP_BOOLOR]

    @property
    def exec_info(self):
        return ExecutionInfo.from_concat(
            self.subs[0].exec_info,
            self.subs[1].exec_info,
            ops_count=1,
            disjunction=True,
        )

    def satisfaction(self, sat_material):
        return Satisfaction.from_concat(
            sat_material, self.subs[0], self.subs[1], disjunction=True
        )

    def dissatisfaction(self):
        return self.subs[1].dissatisfaction() + self.subs[0].dissatisfaction()

    def __repr__(self):
        return f"or_b({','.join(map(str, self.subs))})"


class OrC(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu") and sub_z.p.V

        self.subs = [sub_x, sub_z]

        self.p = Property(
            "V"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = True  # Because sub_z is 'V'
        self.is_expressive = False  # V
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = all(sub.no_timelock_mix for sub in self.subs)

    @property
    def _script(self):
        return self.subs[0]._script + [OP_NOTIF] + self.subs[1]._script + [OP_ENDIF]

    @property
    def exec_info(self):
        exec_info = ExecutionInfo.from_or_uneven(
            self.subs[0].exec_info, self.subs[1].exec_info, ops_count=2
        )
        exec_info.set_undissatisfiable()  # it's V.
        return exec_info

    def satisfaction(self, sat_material):
        return Satisfaction.from_or_uneven(sat_material, self.subs[0], self.subs[1])

    def dissatisfaction(self):
        return Satisfaction.unavailable()  # it's V.

    def __repr__(self):
        return f"or_c({','.join(map(str, self.subs))})"


class OrD(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.has_all("Bdu")
        assert sub_z.p.has_all("B")

        self.subs = [sub_x, sub_z]

        self.p = Property(
            "B"
            + ("z" if sub_x.p.z and sub_z.p.z else "")
            + ("o" if sub_x.p.o and sub_z.p.z else "")
            + ("d" if sub_z.p.d else "")
            + ("u" if sub_z.p.u else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = all(sub.is_forced for sub in self.subs)
        self.is_expressive = all(sub.is_expressive for sub in self.subs)
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = all(sub.no_timelock_mix for sub in self.subs)

    @property
    def _script(self):
        return (
            self.subs[0]._script
            + [OP_IFDUP, OP_NOTIF]
            + self.subs[1]._script
            + [OP_ENDIF]
        )

    @property
    def exec_info(self):
        return ExecutionInfo.from_or_uneven(
            self.subs[0].exec_info, self.subs[1].exec_info, ops_count=3
        )

    def satisfaction(self, sat_material):
        return Satisfaction.from_or_uneven(sat_material, self.subs[0], self.subs[1])

    def dissatisfaction(self):
        return self.subs[1].dissatisfaction() + self.subs[0].dissatisfaction()

    def __repr__(self):
        return f"or_d({','.join(map(str, self.subs))})"


class OrI(Node):
    def __init__(self, sub_x, sub_z):
        assert sub_x.p.type() == sub_z.p.type() and sub_x.p.has_any("BKV")

        self.subs = [sub_x, sub_z]

        self.p = Property(
            sub_x.p.type()
            + ("o" if sub_x.p.z and sub_z.p.z else "")
            + ("d" if sub_x.p.d or sub_z.p.d else "")
            + ("u" if sub_x.p.u and sub_z.p.u else "")
        )
        self.needs_sig = all(sub.needs_sig for sub in self.subs)
        self.is_forced = all(sub.is_forced for sub in self.subs)
        self.is_expressive = (
            sub_x.is_expressive
            and sub_z.is_forced
            or sub_x.is_forced
            and sub_z.is_expressive
        )
        self.is_nonmalleable = all(sub.is_nonmalleable for sub in self.subs) and any(
            sub.needs_sig for sub in self.subs
        )
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        self.no_timelock_mix = all(sub.no_timelock_mix for sub in self.subs)

    @property
    def _script(self):
        return (
            [OP_IF]
            + self.subs[0]._script
            + [OP_ELSE]
            + self.subs[1]._script
            + [OP_ENDIF]
        )

    @property
    def exec_info(self):
        return ExecutionInfo.from_or_even(
            self.subs[0].exec_info, self.subs[1].exec_info, ops_count=3
        )

    def satisfaction(self, sat_material):
        return (self.subs[0].satisfaction(sat_material) + Satisfaction([b"\x01"])) | (
            self.subs[1].satisfaction(sat_material) + Satisfaction([b""])
        )

    def dissatisfaction(self):
        return (self.subs[0].dissatisfaction() + Satisfaction(witness=[b"\x01"])) | (
            self.subs[1].dissatisfaction() + Satisfaction(witness=[b""])
        )

    def __repr__(self):
        return f"or_i({','.join(map(str, self.subs))})"


class AndOr(Node):
    def __init__(self, sub_x, sub_y, sub_z):
        assert sub_x.p.has_all("Bdu")
        assert sub_y.p.type() == sub_z.p.type() and sub_y.p.has_any("BKV")

        self.subs = [sub_x, sub_y, sub_z]

        self.p = Property(
            sub_y.p.type()
            + ("z" if sub_x.p.z and sub_y.p.z and sub_z.p.z else "")
            + (
                "o"
                if sub_x.p.z
                and sub_y.p.o
                and sub_z.p.o
                or sub_x.p.o
                and sub_y.p.z
                and sub_z.p.z
                else ""
            )
            + ("d" if sub_z.p.d else "")
            + ("u" if sub_y.p.u and sub_z.p.u else "")
        )
        self.needs_sig = sub_x.needs_sig and (sub_y.needs_sig or sub_z.needs_sig)
        self.is_forced = sub_z.is_forced and (sub_x.needs_sig or sub_y.is_forced)
        self.is_expressive = (
            sub_x.is_expressive
            and sub_z.is_expressive
            and (sub_x.needs_sig or sub_y.is_forced)
        )
        self.is_nonmalleable = (
            all(sub.is_nonmalleable for sub in self.subs)
            and any(sub.needs_sig for sub in self.subs)
            and sub_x.is_expressive
        )
        self.abs_heightlocks = any(sub.abs_heightlocks for sub in self.subs)
        self.rel_heightlocks = any(sub.rel_heightlocks for sub in self.subs)
        self.abs_timelocks = any(sub.abs_timelocks for sub in self.subs)
        self.rel_timelocks = any(sub.rel_timelocks for sub in self.subs)
        # X and Y, or Z. So we have a mix if any contain a timelock mix, or
        # there is a mix between X and Y.
        self.no_timelock_mix = all(sub.no_timelock_mix for sub in self.subs) and not (
            any(sub.rel_timelocks for sub in [sub_x, sub_y])
            and any(sub.rel_heightlocks for sub in [sub_x, sub_y])
            or any(sub.abs_timelocks for sub in [sub_x, sub_y])
            and any(sub.abs_heightlocks for sub in [sub_x, sub_y])
        )

    @property
    def _script(self):
        return (
            self.subs[0]._script
            + [OP_NOTIF]
            + self.subs[2]._script
            + [OP_ELSE]
            + self.subs[1]._script
            + [OP_ENDIF]
        )

    @property
    def exec_info(self):
        return ExecutionInfo.from_andor_uneven(
            self.subs[0].exec_info,
            self.subs[1].exec_info,
            self.subs[2].exec_info,
            ops_count=3,
        )

    def satisfaction(self, sat_material):
        # (A and B) or (!A and C)
        return (
            self.subs[1].satisfaction(sat_material)
            + self.subs[0].satisfaction(sat_material)
        ) | (self.subs[2].satisfaction(sat_material) + self.subs[0].dissatisfaction())

    def dissatisfaction(self):
        # Dissatisfy X and Z
        return self.subs[2].dissatisfaction() + self.subs[0].dissatisfaction()

    def __repr__(self):
        return f"andor({','.join(map(str, self.subs))})"


class AndN(AndOr):
    def __init__(self, sub_x, sub_y):
        AndOr.__init__(self, sub_x, sub_y, Just0())

    def __repr__(self):
        return f"and_n({self.subs[0]},{self.subs[1]})"


class Thresh(Node):
    def __init__(self, k, subs):
        n = len(subs)
        assert 1 <= k <= n

        self.k = k
        self.subs = subs

        all_z = True
        all_z_but_one_odu = False
        all_e = True
        all_m = True
        s_count = 0
        # If k == 1, just check each child for k
        if k > 1:
            self.abs_heightlocks = subs[0].abs_heightlocks
            self.rel_heightlocks = subs[0].rel_heightlocks
            self.abs_timelocks = subs[0].abs_timelocks
            self.rel_timelocks = subs[0].rel_timelocks
        else:
            self.no_timelock_mix = True

        assert subs[0].p.has_all("Bdu")
        for sub in subs[1:]:
            assert sub.p.has_all("Wdu")
            if not sub.p.z:
                if all_z_but_one_odu:
                    # Fails "all 'z' but one"
                    all_z_but_one_odu = False
                if all_z and sub.p.has_all("odu"):
                    # They were all 'z' up to now.
                    all_z_but_one_odu = True
                all_z = False
            all_e = all_e and sub.is_expressive
            all_m = all_m and sub.is_nonmalleable
            if sub.needs_sig:
                s_count += 1
            if k > 1:
                self.abs_heightlocks |= sub.abs_heightlocks
                self.rel_heightlocks |= sub.rel_heightlocks
                self.abs_timelocks |= sub.abs_timelocks
                self.rel_timelocks |= sub.rel_timelocks
            else:
                self.no_timelock_mix &= sub.no_timelock_mix

        self.p = Property(
            "Bdu" + ("z" if all_z else "") + ("o" if all_z_but_one_odu else "")
        )
        self.needs_sig = s_count >= n - k
        self.is_forced = False  # All subs need to be 'd'
        self.is_expressive = all_e and s_count == n
        self.is_nonmalleable = all_e and s_count >= n - k
        if k > 1:
            self.no_timelock_mix = not (
                self.abs_heightlocks
                and self.abs_timelocks
                or self.rel_heightlocks
                and self.rel_timelocks
            )

    @property
    def _script(self):
        return (
            self.subs[0]._script
            + sum(((sub._script + [OP_ADD]) for sub in self.subs[1:]), start=[])
            + [self.k, OP_EQUAL]
        )

    @property
    def exec_info(self):
        return ExecutionInfo.from_thresh(self.k, [sub.exec_info for sub in self.subs])

    def satisfaction(self, sat_material):
        return Satisfaction.from_thresh(sat_material, self.k, self.subs)

    def dissatisfaction(self):
        return sum(
            [sub.dissatisfaction() for sub in self.subs], start=Satisfaction(witness=[])
        )

    def __repr__(self):
        return f"thresh({self.k},{','.join(map(str, self.subs))})"


class WrapperNode(Node):
    """A virtual base class for wrappers.

    Don't instanciate it directly, use concret wrapper fragments instead.
    """

    def __init__(self, sub):
        self.subs = [sub]

        # Properties for most wrappers are directly inherited. When it's not, they
        # are overriden in the fragment's __init__.
        self.needs_sig = sub.needs_sig
        self.is_forced = sub.is_forced
        self.is_expressive = sub.is_expressive
        self.is_nonmalleable = sub.is_nonmalleable
        self.abs_heightlocks = sub.abs_heightlocks
        self.rel_heightlocks = sub.rel_heightlocks
        self.abs_timelocks = sub.abs_timelocks
        self.rel_timelocks = sub.rel_timelocks
        self.no_timelock_mix = not (
            self.abs_heightlocks
            and self.abs_timelocks
            or self.rel_heightlocks
            and self.rel_timelocks
        )

    @property
    def sub(self):
        # Wrapper have a single sub
        return self.subs[0]

    def satisfaction(self, sat_material):
        # Most wrappers are satisfied this way, for special cases it's overriden.
        return self.subs[0].satisfaction(sat_material)

    def dissatisfaction(self):
        # Most wrappers are satisfied this way, for special cases it's overriden.
        return self.subs[0].dissatisfaction()

    def skip_colon(self):
        # We need to check this because of the pk() and pkh() aliases.
        if isinstance(self.subs[0], WrapC) and isinstance(
            self.subs[0].subs[0], (Pk, Pkh)
        ):
            return False
        return isinstance(self.subs[0], WrapperNode)


class WrapA(WrapperNode):
    def __init__(self, sub):
        assert sub.p.B
        WrapperNode.__init__(self, sub)

        self.p = Property("W" + "".join(c for c in "ud" if getattr(sub.p, c)))

    @property
    def _script(self):
        return [OP_TOALTSTACK] + self.sub._script + [OP_FROMALTSTACK]

    @property
    def exec_info(self):
        return ExecutionInfo.from_wrap(self.sub.exec_info, ops_count=2)

    def __repr__(self):
        # Don't duplicate colons
        if self.skip_colon():
            return f"a{self.subs[0]}"
        return f"a:{self.subs[0]}"


class WrapS(WrapperNode):
    def __init__(self, sub):
        assert sub.p.has_all("Bo")
        WrapperNode.__init__(self, sub)

        self.p = Property("W" + "".join(c for c in "ud" if getattr(sub.p, c)))

    @property
    def _script(self):
        return [OP_SWAP] + self.sub._script

    @property
    def exec_info(self):
        return ExecutionInfo.from_wrap(self.sub.exec_info, ops_count=1)

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"s{self.subs[0]}"
        return f"s:{self.subs[0]}"


class WrapC(WrapperNode):
    def __init__(self, sub):
        assert sub.p.K
        WrapperNode.__init__(self, sub)

        # FIXME: shouldn't n and d be default props on the website?
        self.p = Property("Bu" + "".join(c for c in "dno" if getattr(sub.p, c)))

    @property
    def _script(self):
        return self.sub._script + [OP_CHECKSIG]

    @property
    def exec_info(self):
        # FIXME: should need_sig be set to True here instead of in keys?
        return ExecutionInfo.from_wrap(self.sub.exec_info, ops_count=1, sat=1, dissat=1)

    def __repr__(self):
        # Special case of aliases
        if isinstance(self.subs[0], Pk):
            return f"pk({self.subs[0].pubkey})"
        if isinstance(self.subs[0], Pkh):
            return f"pkh({self.subs[0].pubkey})"
        # Avoid duplicating colons
        if self.skip_colon():
            return f"c{self.subs[0]}"
        return f"c:{self.subs[0]}"


class WrapT(AndV, WrapperNode):
    def __init__(self, sub):
        AndV.__init__(self, sub, Just1())

    def is_wrapper(self):
        return True

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"t{self.subs[0]}"
        return f"t:{self.subs[0]}"


class WrapD(WrapperNode):
    def __init__(self, sub):
        assert sub.p.has_all("Vz")
        WrapperNode.__init__(self, sub)

        self.p = Property("Bond")
        self.is_forced = True  # sub is V
        self.is_expressive = True  # sub is V, and we add a single dissat

    @property
    def _script(self):
        return [OP_DUP, OP_IF] + self.sub._script + [OP_ENDIF]

    @property
    def exec_info(self):
        return ExecutionInfo.from_wrap_dissat(
            self.sub.exec_info, ops_count=3, sat=1, dissat=1
        )

    def satisfaction(self, sat_material):
        return Satisfaction(witness=[b"\x01"]) + self.subs[0].satisfaction(sat_material)

    def dissatisfaction(self):
        return Satisfaction(witness=[b""])

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"d{self.subs[0]}"
        return f"d:{self.subs[0]}"


class WrapV(WrapperNode):
    def __init__(self, sub):
        assert sub.p.B
        WrapperNode.__init__(self, sub)

        self.p = Property("V" + "".join(c for c in "zon" if getattr(sub.p, c)))
        self.is_forced = True  # V
        self.is_expressive = False  # V

    @property
    def _script(self):
        if self.sub._script[-1] == OP_CHECKSIG:
            return self.sub._script[:-1] + [OP_CHECKSIGVERIFY]
        elif self.sub._script[-1] == OP_CHECKMULTISIG:
            return self.sub._script[:-1] + [OP_CHECKMULTISIGVERIFY]
        elif self.sub._script[-1] == OP_EQUAL:
            return self.sub._script[:-1] + [OP_EQUALVERIFY]
        return self.sub._script + [OP_VERIFY]

    @property
    def exec_info(self):
        verify_cost = int(self._script[-1] == OP_VERIFY)
        return ExecutionInfo.from_wrap(self.sub.exec_info, ops_count=verify_cost)

    def dissatisfaction(self):
        return Satisfaction.unavailable()  # It's V.

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"v{self.subs[0]}"
        return f"v:{self.subs[0]}"


class WrapJ(WrapperNode):
    def __init__(self, sub):
        assert sub.p.has_all("Bn")
        WrapperNode.__init__(self, sub)

        self.p = Property("Bnd" + "".join(c for c in "ou" if getattr(sub.p, c)))
        self.is_forced = False  # d
        self.is_expressive = sub.is_forced

    @property
    def _script(self):
        return [OP_SIZE, OP_0NOTEQUAL, OP_IF, *self.sub._script, OP_ENDIF]

    @property
    def exec_info(self):
        return ExecutionInfo.from_wrap_dissat(self.sub.exec_info, ops_count=4, dissat=1)

    def dissatisfaction(self):
        return Satisfaction(witness=[b""])

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"j{self.subs[0]}"
        return f"j:{self.subs[0]}"


class WrapN(WrapperNode):
    def __init__(self, sub):
        assert sub.p.B
        WrapperNode.__init__(self, sub)

        self.p = Property("Bu" + "".join(c for c in "zond" if getattr(sub.p, c)))

    @property
    def _script(self):
        return [*self.sub._script, OP_0NOTEQUAL]

    @property
    def exec_info(self):
        return ExecutionInfo.from_wrap(self.sub.exec_info, ops_count=1)

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"n{self.subs[0]}"
        return f"n:{self.subs[0]}"


class WrapL(OrI, WrapperNode):
    def __init__(self, sub):
        OrI.__init__(self, Just0(), sub)

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"l{self.subs[1]}"
        return f"l:{self.subs[1]}"


class WrapU(OrI, WrapperNode):
    def __init__(self, sub):
        OrI.__init__(self, sub, Just0())

    def __repr__(self):
        # Avoid duplicating colons
        if self.skip_colon():
            return f"u{self.subs[0]}"
        return f"u:{self.subs[0]}"
