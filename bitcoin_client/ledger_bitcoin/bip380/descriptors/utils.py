"""Utilities for working with descriptors."""
import coincurve
import hashlib


def tagged_hash(tag, data):
    ss = hashlib.sha256(tag.encode("utf-8")).digest()
    ss += ss
    ss += data
    return hashlib.sha256(ss).digest()


def taproot_tweak(pubkey_bytes, merkle_root):
    assert isinstance(pubkey_bytes, bytes) and len(pubkey_bytes) == 32
    assert isinstance(merkle_root, bytes)

    t = tagged_hash("TapTweak", pubkey_bytes + merkle_root)
    xonly_pubkey = coincurve.PublicKeyXOnly(pubkey_bytes)
    xonly_pubkey.tweak_add(t)  # TODO: error handling

    return xonly_pubkey
