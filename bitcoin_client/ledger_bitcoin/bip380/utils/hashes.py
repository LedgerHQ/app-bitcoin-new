"""
Common Bitcoin hashes.
"""

import hashlib
from .ripemd_fallback import ripemd160_fallback


def sha256(data):
    """{data} must be bytes, returns sha256(data)"""
    assert isinstance(data, bytes)
    return hashlib.sha256(data).digest()


def hash160(data):
    """{data} must be bytes, returns ripemd160(sha256(data))"""
    assert isinstance(data, bytes)
    if 'ripemd160' in hashlib.algorithms_available:
        return hashlib.new("ripemd160", sha256(data)).digest()
    return ripemd160_fallback(sha256(data))
