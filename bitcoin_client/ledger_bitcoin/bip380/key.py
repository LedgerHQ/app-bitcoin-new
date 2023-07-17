import coincurve
import copy

from bip32 import BIP32, HARDENED_INDEX
from bip32.utils import _deriv_path_str_to_list
from .utils.hashes import hash160
from enum import Enum, auto


def is_raw_key(obj):
    return isinstance(obj, (coincurve.PublicKey, coincurve.PublicKeyXOnly))


class DescriptorKeyError(Exception):
    def __init__(self, message):
        self.message = message


class DescriporKeyOrigin:
    """The origin of a key in a descriptor.

    See https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions.
    """

    def __init__(self, fingerprint, path):
        assert isinstance(fingerprint, bytes) and isinstance(path, list)

        self.fingerprint = fingerprint
        self.path = path

    def from_str(origin_str):
        # Origing starts and ends with brackets
        if not origin_str.startswith("[") or not origin_str.endswith("]"):
            raise DescriptorKeyError(f"Insane origin: '{origin_str}'")
        # At least 8 hex characters + brackets
        if len(origin_str) < 10:
            raise DescriptorKeyError(f"Insane origin: '{origin_str}'")

        # For the fingerprint, just read the 4 bytes.
        try:
            fingerprint = bytes.fromhex(origin_str[1:9])
        except ValueError:
            raise DescriptorKeyError(f"Insane fingerprint in origin: '{origin_str}'")
        # For the path, we (how bad) reuse an internal helper from python-bip32.
        path = []
        if len(origin_str) > 10:
            if origin_str[9] != "/":
                raise DescriptorKeyError(f"Insane path in origin: '{origin_str}'")
            # The helper operates on "m/10h/11/12'/13", so give it a "m".
            dummy = "m"
            try:
                path = _deriv_path_str_to_list(dummy + origin_str[9:-1])
            except ValueError:
                raise DescriptorKeyError(f"Insane path in origin: '{origin_str}'")

        return DescriporKeyOrigin(fingerprint, path)


class KeyPathKind(Enum):
    FINAL = auto()
    WILDCARD_UNHARDENED = auto()
    WILDCARD_HARDENED = auto()

    def is_wildcard(self):
        return self in [KeyPathKind.WILDCARD_HARDENED, KeyPathKind.WILDCARD_UNHARDENED]


def parse_index(index_str):
    """Parse a derivation index, as contained in a derivation path."""
    assert isinstance(index_str, str)

    try:
        # if HARDENED
        if index_str[-1:] in ["'", "h", "H"]:
            return int(index_str[:-1]) + HARDENED_INDEX
        else:
            return int(index_str)
    except ValueError as e:
        raise DescriptorKeyError(f"Invalid derivation index {index_str}: '{e}'")


class DescriptorKeyPath:
    """The derivation path of a key in a descriptor.

    See https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki#key-expressions
    as well as BIP389 for multipath expressions.
    """

    def __init__(self, paths, kind):
        assert (
            isinstance(paths, list)
            and isinstance(kind, KeyPathKind)
            and len(paths) > 0
            and all(isinstance(p, list) for p in paths)
        )

        self.paths = paths
        self.kind = kind

    def is_multipath(self):
        """Whether this derivation path actually contains multiple of them."""
        return len(self.paths) > 1

    def from_str(path_str):
        if len(path_str) < 2:
            raise DescriptorKeyError(f"Insane key path: '{path_str}'")
        if path_str[0] != "/":
            raise DescriptorKeyError(f"Insane key path: '{path_str}'")

        # Determine whether this key may be derived.
        kind = KeyPathKind.FINAL
        if len(path_str) > 2 and path_str[-3:] in ["/*'", "/*h", "/*H"]:
            kind = KeyPathKind.WILDCARD_HARDENED
            path_str = path_str[:-3]
        elif len(path_str) > 1 and path_str[-2:] == "/*":
            kind = KeyPathKind.WILDCARD_UNHARDENED
            path_str = path_str[:-2]

        paths = [[]]
        if len(path_str) == 0:
            return DescriptorKeyPath(paths, kind)

        for index in path_str[1:].split("/"):
            # If this is a multipath expression, of the form '<X;X>'
            if (
                index.startswith("<")
                and index.endswith(">")
                and ";" in index
                and len(index) >= 5
            ):
                # Can't have more than one multipath expression
                if len(paths) > 1:
                    raise DescriptorKeyError(
                        f"May only have a single multipath step in derivation path: '{path_str}'"
                    )
                indexes = index[1:-1].split(";")
                paths = [copy.copy(paths[0]) for _ in indexes]
                for i, der_index in enumerate(indexes):
                    paths[i].append(parse_index(der_index))
            else:
                # This is a "single index" expression.
                for path in paths:
                    path.append(parse_index(index))
        return DescriptorKeyPath(paths, kind)


class DescriptorKey:
    """A Bitcoin key to be used in Output Script Descriptors.

    May be an extended or raw public key.
    """

    def __init__(self, key, x_only=False):
        # Information about the origin of this key.
        self.origin = None
        # If it is an xpub, a path toward a child key of that xpub.
        self.path = None
        # Whether to only create x-only public keys.
        self.x_only = x_only
        # Whether to serialize to string representation without the sign byte.
        # This is necessary to roundtrip 33-bytes keys under Taproot context.
        self.ser_x_only = x_only

        if isinstance(key, bytes):
            if len(key) == 32:
                key_cls = coincurve.PublicKeyXOnly
                self.x_only = True
                self.ser_x_only = True
            elif len(key) == 33:
                key_cls = coincurve.PublicKey
                self.ser_x_only = False
            else:
                raise DescriptorKeyError(
                    "Only compressed and x-only keys are supported"
                )
            try:
                self.key = key_cls(key)
            except ValueError as e:
                raise DescriptorKeyError(f"Public key parsing error: '{str(e)}'")

        elif isinstance(key, BIP32):
            self.key = key

        elif isinstance(key, str):
            # Try parsing an optional origin prepended to the key
            splitted_key = key.split("]", maxsplit=1)
            if len(splitted_key) == 2:
                origin, key = splitted_key
                self.origin = DescriporKeyOrigin.from_str(origin + "]")

            # Is it a raw key?
            if len(key) in (64, 66):
                pk_cls = coincurve.PublicKey
                if len(key) == 64:
                    pk_cls = coincurve.PublicKeyXOnly
                    self.x_only = True
                    self.ser_x_only = True
                else:
                    self.ser_x_only = False
                try:
                    self.key = pk_cls(bytes.fromhex(key))
                except ValueError as e:
                    raise DescriptorKeyError(f"Public key parsing error: '{str(e)}'")
            # If not it must be an xpub.
            else:
                # There may be an optional path appended to the xpub.
                splitted_key = key.split("/", maxsplit=1)
                if len(splitted_key) == 2:
                    key, path = splitted_key
                    self.path = DescriptorKeyPath.from_str("/" + path)

                try:
                    self.key = BIP32.from_xpub(key)
                except ValueError as e:
                    raise DescriptorKeyError(f"Xpub parsing error: '{str(e)}'")

        else:
            raise DescriptorKeyError(
                "Invalid parameter type: expecting bytes, hex str or BIP32 instance."
            )

    def __repr__(self):
        key = ""

        def ser_index(key, der_index):
            # If this a hardened step, deduce the threshold and mark it.
            if der_index < HARDENED_INDEX:
                return str(der_index)
            else:
                return f"{der_index - 2**31}'"

        def ser_paths(key, paths):
            assert len(paths) > 0

            for i, der_index in enumerate(paths[0]):
                # If this is a multipath expression, write the multi-index step accordingly
                if len(paths) > 1 and paths[1][i] != der_index:
                    key += "/<"
                    for j, path in enumerate(paths):
                        key += ser_index(key, path[i])
                        if j < len(paths) - 1:
                            key += ";"
                    key += ">"
                else:
                    key += "/" + ser_index(key, der_index)

            return key

        if self.origin is not None:
            key += f"[{self.origin.fingerprint.hex()}"
            key = ser_paths(key, [self.origin.path])
            key += "]"

        if isinstance(self.key, BIP32):
            key += self.key.get_xpub()
        else:
            assert is_raw_key(self.key)
            raw_key = self.key.format()
            if len(raw_key) == 33 and self.ser_x_only:
                raw_key = raw_key[1:]
            key += raw_key.hex()

        if self.path is not None:
            key = ser_paths(key, self.path.paths)
            if self.path.kind == KeyPathKind.WILDCARD_UNHARDENED:
                key += "/*"
            elif self.path.kind == KeyPathKind.WILDCARD_HARDENED:
                key += "/*'"

        return key

    def is_multipath(self):
        """Whether this key contains more than one derivation path."""
        return self.path is not None and self.path.is_multipath()

    def derivation_path(self):
        """Get the single derivation path for this key.

        Will raise if it has multiple, and return None if it doesn't have any.
        """
        if self.path is None:
            return None
        if self.path.is_multipath():
            raise DescriptorKeyError(
                f"Key has multiple derivation paths: {self.path.paths}"
            )
        return self.path.paths[0]

    def bytes(self):
        """Get this key as raw bytes.

        Will raise if this key contains multiple derivation paths.
        """
        if is_raw_key(self.key):
            raw = self.key.format()
            if self.x_only and len(raw) == 33:
                return raw[1:]
            assert len(raw) == 32 or not self.x_only
            return raw
        else:
            assert isinstance(self.key, BIP32)
            path = self.derivation_path()
            if path is None:
                return self.key.pubkey
            assert not self.path.kind.is_wildcard()  # TODO: real errors
            return self.key.get_pubkey_from_path(path)

    def derive(self, index):
        """Derive the key at the given index.

        Will raise if this key contains multiple derivation paths.
        A no-op if the key isn't a wildcard. Will start from 2**31 if the key is a "hardened
        wildcard".
        """
        assert isinstance(index, int)
        if (
            self.path is None
            or self.path.is_multipath()
            or self.path.kind == KeyPathKind.FINAL
        ):
            return
        assert isinstance(self.key, BIP32)

        if self.path.kind == KeyPathKind.WILDCARD_HARDENED:
            index += 2 ** 31
        assert index < 2 ** 32

        if self.origin is None:
            fingerprint = hash160(self.key.pubkey)[:4]
            self.origin = DescriporKeyOrigin(fingerprint, [index])
        else:
            self.origin.path.append(index)

        # This can't fail now.
        path = self.derivation_path()
        # TODO(bip32): have a way to derive without roundtripping through string ser.
        self.key = BIP32.from_xpub(self.key.get_xpub_from_path(path + [index]))
        self.path = None
