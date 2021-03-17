from bitcoin_client.bitcoin_cmd_builder import AddrType
from bitcoin_client.exception import DenyError
from utils import automation
from typing import List

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der


import pytest


def serialize_str(pubkey: str) -> bytes:
    return len(pubkey).to_bytes(1, byteorder="big") + pubkey.encode("latin-1")

def serialize_multisig_wallet(name: str, threshold: int, n_keys: int, pubkeys: List[str]) -> bytes:
    return (b'\0'  # wallet type
        + serialize_str(name)
        + threshold.to_bytes(1, byteorder="big")
        + n_keys.to_bytes(1, byteorder="big")
        + b''.join(serialize_str(key) for key in pubkeys))


# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin
# root extended private key: xprv9s21ZrQH143K4QDdULpHJyaEf1RKEhkxHaUReQSGHQ9Qhqzymp1tER1oBLqxePyRHepCzh3wnEoQR77ygSiEXzx9hVF7E8KEGqHLQqEmF9v
# root private key (hex): 34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938
# root extended public key: xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12
# root compressed public key (hex): 0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db

root_compressed_pk = "0251ec84e33a3119486461a44240e906ff94bf40cf807b025b1ca43332b80dc9db"

@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept(cmd):
    name = "Cold storage"
    threshold = 2
    n_keys = 3
    pubkeys = ["xpub1", "xpub2", "xpub3"]

    wallet_id, sig = cmd.register_wallet(
        wallet_type=0,
        name=name,
        threshold=threshold,
        n_keys=n_keys,
        pubkeys=pubkeys
    )

    wallet_serialized = serialize_multisig_wallet(name, threshold, n_keys, pubkeys)

    assert sha256(wallet_serialized).digest().hex() == wallet_id

    pk: VerifyingKey = VerifyingKey.from_string(
        bytes.fromhex(root_compressed_pk),
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=bytes.fromhex(sig),
                     data=wallet_serialized,
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True

@automation("automations/register_wallet_reject.json")
def test_register_wallet_reject_header(cmd):
    with pytest.raises(DenyError):
        cmd.register_wallet(
            wallet_type=0,
            name="Cold storage",
            threshold=2,
            n_keys=3,
            pubkeys=["xpub1", "xpub2", "xpub3"]
        )
