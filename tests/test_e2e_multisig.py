
from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet, AddressType

from utils import automation
from typing import List
from bitcoin_client.wallet import AddressType

import pytest


@automation("automations/register_wallet_accept.json")
def test_register_and_get_address(cmd, speculos_globals):
    # test for a native segwit wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[61e4f658]xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            "[acc1fe38]xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
            "[ba16e65d]xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
        ]
    )

    wallet_id, wallet_sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=wallet_sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


    res = cmd.get_wallet_address(wallet, wallet_sig, 0)

    assert res == "bc1qj9y4fj9vq50qkr8xg3lz6tzvj53t87n36d095z2v6fp98zmedw3sakcau0"
