from ...bip380.key import DescriptorKey
from ...bip380.miniscript import Node
from ...bip380.utils.hashes import sha256, hash160
from ...bip380.utils.script import (
    CScript,
    OP_1,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
)

from .checksum import descsum_create
from .errors import DescriptorParsingError
from .parsing import descriptor_from_str
from .utils import taproot_tweak


class Descriptor:
    """A Bitcoin Output Script Descriptor."""

    def from_str(desc_str, strict=False):
        """Parse a Bitcoin Output Script Descriptor from its string representation.

        :param strict: whether to require the presence of a checksum.
        """
        desc = descriptor_from_str(desc_str, strict)

        # BIP389 prescribes that no two multipath key expressions in a single descriptor
        # have different length.
        multipath_len = None
        for key in desc.keys:
            if key.is_multipath():
                m_len = len(key.path.paths)
                if multipath_len is None:
                    multipath_len = m_len
                elif multipath_len != m_len:
                    raise DescriptorParsingError(
                        f"Descriptor contains multipath key expressions with varying length: '{desc_str}'."
                    )

        return desc

    @property
    def script_pubkey(self):
        """Get the ScriptPubKey (output 'locking' Script) for this descriptor."""
        # To be implemented by derived classes
        raise NotImplementedError

    @property
    def script_sighash(self):
        """Get the Script to be committed to by the signature hash of a spending transaction."""
        # To be implemented by derived classes
        raise NotImplementedError

    @property
    def keys(self):
        """Get the list of all keys from this descriptor, in order of apparition."""
        # To be implemented by derived classes
        raise NotImplementedError

    def derive(self, index):
        """Derive the key at the given derivation index.

        A no-op if the key isn't a wildcard. Will start from 2**31 if the key is a "hardened
        wildcard".
        """
        assert isinstance(index, int)
        for key in self.keys:
            key.derive(index)

    def satisfy(self, *args, **kwargs):
        """Get the witness stack to spend from this descriptor.

        Various data may need to be passed as parameters to meet the locking
        conditions set by the Script.
        """
        # To be implemented by derived classes
        raise NotImplementedError

    def copy(self):
        """Get a copy of this descriptor."""
        # FIXME: do something nicer than roundtripping through string ser
        return Descriptor.from_str(str(self))

    def is_multipath(self):
        """Whether this descriptor contains multipath key expression(s)."""
        return any(k.is_multipath() for k in self.keys)

    def singlepath_descriptors(self):
        """Get a list of descriptors that only contain keys that don't have multiple
        derivation paths.
        """
        singlepath_descs = [self.copy()]

        # First figure out the number of descriptors there will be
        for key in self.keys:
            if key.is_multipath():
                singlepath_descs += [
                    self.copy() for _ in range(len(key.path.paths) - 1)
                ]
                break

        # Return early if there was no multipath key expression
        if len(singlepath_descs) == 1:
            return singlepath_descs

        # Then use one path for each
        for i, desc in enumerate(singlepath_descs):
            for key in desc.keys:
                if key.is_multipath():
                    assert len(key.path.paths) == len(singlepath_descs)
                    key.path.paths = key.path.paths[i: i + 1]

        assert all(not d.is_multipath() for d in singlepath_descs)
        return singlepath_descs


# TODO: add methods to give access to all the Miniscript analysis
class WshDescriptor(Descriptor):
    """A Segwit v0 P2WSH Output Script Descriptor."""

    def __init__(self, witness_script):
        assert isinstance(witness_script, Node)
        self.witness_script = witness_script

    def __repr__(self):
        return descsum_create(f"wsh({self.witness_script})")

    @property
    def script_pubkey(self):
        witness_program = sha256(self.witness_script.script)
        return CScript([0, witness_program])

    @property
    def script_sighash(self):
        return self.witness_script.script

    @property
    def keys(self):
        return self.witness_script.keys

    def satisfy(self, sat_material=None):
        """Get the witness stack to spend from this descriptor.

        :param sat_material: a miniscript.satisfaction.SatisfactionMaterial with data
                             available to fulfill the conditions set by the Script.
        """
        sat = self.witness_script.satisfy(sat_material)
        if sat is not None:
            return sat + [self.witness_script.script]


class WpkhDescriptor(Descriptor):
    """A Segwit v0 P2WPKH Output Script Descriptor."""

    def __init__(self, pubkey):
        assert isinstance(pubkey, DescriptorKey)
        self.pubkey = pubkey

    def __repr__(self):
        return descsum_create(f"wpkh({self.pubkey})")

    @property
    def script_pubkey(self):
        witness_program = hash160(self.pubkey.bytes())
        return CScript([0, witness_program])

    @property
    def script_sighash(self):
        key_hash = hash160(self.pubkey.bytes())
        return CScript([OP_DUP, OP_HASH160, key_hash, OP_EQUALVERIFY, OP_CHECKSIG])

    @property
    def keys(self):
        return [self.pubkey]

    def satisfy(self, signature):
        """Get the witness stack to spend from this descriptor.

        :param signature: a signature (in bytes) for the pubkey from the descriptor.
        """
        assert isinstance(signature, bytes)
        return [signature, self.pubkey.bytes()]


class TrDescriptor(Descriptor):
    """A Pay-to-Taproot Output Script Descriptor."""

    def __init__(self, internal_key):
        assert isinstance(internal_key, DescriptorKey) and internal_key.x_only
        self.internal_key = internal_key

    def __repr__(self):
        return descsum_create(f"tr({self.internal_key})")

    def output_key(self):
        # "If the spending conditions do not require a script path, the output key
        # should commit to an unspendable script path" (see BIP341, BIP386)
        return taproot_tweak(self.internal_key.bytes(), b"").format()

    @property
    def script_pubkey(self):
        return CScript([OP_1, self.output_key()])

    @property
    def keys(self):
        return [self.internal_key]

    def satisfy(self, sat_material=None):
        """Get the witness stack to spend from this descriptor.

        :param sat_material: a miniscript.satisfaction.SatisfactionMaterial with data
                             available to spend from the key path or any of the leaves.
        """
        out_key = self.output_key()
        if out_key in sat_material.signatures:
            return [sat_material.signatures[out_key]]

        return
