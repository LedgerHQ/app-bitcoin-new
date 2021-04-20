from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import AddressType, MultisigWallet, AddressType
from utils import automation
from typing import List

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

import pytest


def get_wallet(addr_type: AddressType) -> MultisigWallet:
    return MultisigWallet(
        name="Cold storage",
        address_type=addr_type,
        threshold=2,
        keys_info=[
            "[61e4f658]xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            "[acc1fe38]xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
            "[ba16e65d]xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
        ]
    )


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_legacy(cmd, speculos_globals):
    wallet = get_wallet(AddressType.LEGACY)

    wallet_id, sig = cmd.register_wallet(wallet)
    print(f"SIGNATURE for LEGACY: {sig.hex()}")

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_wit(cmd, speculos_globals):
    wallet = get_wallet(AddressType.WIT)

    wallet_id, sig = cmd.register_wallet(wallet)
    print(f"SIGNATURE for WIT: {sig.hex()}")

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_sh_wit(cmd, speculos_globals):
    wallet = get_wallet(AddressType.SH_WIT)

    wallet_id, sig = cmd.register_wallet(wallet)
    print(f"SIGNATURE for SH_WIT: {sig.hex()}")

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_reject.json")
def test_register_wallet_reject_header(cmd):
    wallet = get_wallet(AddressType.LEGACY)
    with pytest.raises(DenyError):
        cmd.register_wallet(wallet)


# TODO: add more tests for:
#  - rejections at different stages
#  - responses to different types of wrong data from the host
