import hashlib

from mnemonic import Mnemonic
from bip32 import BIP32

from .slip21 import Slip21Node

mnemo = Mnemonic("english")

DEFAULT_SPECULOS_MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

WALLET_POLICY_SLIP21_LABEL = b"LEDGER-Wallet policy"


default_settings = {
    # mnemonic to use when running speculos
    "mnemonic": DEFAULT_SPECULOS_MNEMONIC,
    # path of the automation file to use for speculos if used, or None
    "automation_file": None
}


def test_settings(s: dict):
    """Decorator that adds the given settings to the "test_settings" field of a test function."""
    def decorator(func):
        if not hasattr(func, 'test_settings'):
            func.test_settings = default_settings.copy()
        func.test_settings.update(s)
        return func
    return decorator


def automation(filename: str):
    """Adds the automation_file setting to use `filename` as the Speculos automation file."""
    return test_settings({"automation_file": filename})


def mnemonic(mnemo: str):
    """Adds the `mnemonic` setting to the test settings."""
    return test_settings({"mnemonic": mnemo})


def ripemd160(x: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(x)
    return h.digest()


def sha256(s: bytes) -> bytes:
    return hashlib.new('sha256', s).digest()


def hash160(s: bytes) -> bytes:
    return ripemd160(sha256(s))


def hash256(s: bytes) -> bytes:
    return sha256(sha256(s))


class SpeculosGlobals:
    def __init__(self, mnemonic: str, network: str = "test"):
        if network not in ["main", "test"]:
            raise ValueError(f"Invalid network: {network}")

        self.mnemonic = mnemonic
        self.seed = mnemo.to_seed(mnemonic)
        bip32 = BIP32.from_seed(self.seed, network)
        self.master_extended_privkey = bip32.get_xpriv()
        self.master_extended_pubkey = bip32.get_xpub()
        self.master_key_fingerprint = int.from_bytes(
            hash160(bip32.pubkey)[0:4], byteorder="big")
        self.master_compressed_pubkey = bip32.pubkey.hex()
        slip21_root = Slip21Node.from_seed(self.seed)
        self.wallet_registration_key = slip21_root.derive_child(
            WALLET_POLICY_SLIP21_LABEL).key
