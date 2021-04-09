from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet, AddressType

from utils import automation
from typing import List
from bitcoin_client.bitcoin_cmd_builder import ScriptAddrType

import pytest


def test_get_wallet_address_legacy(cmd):
    # test for a legacy p2sh wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            "[61e4f658]xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            "[acc1fe38]xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
            "[ba16e65d]xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
        ]
    )
    wallet_sig = bytes.fromhex("3044022006ca7061dfe7f5c4f8e5ae086303d1462e4136af600bacbfaeedf656aeaed09302204b8aa84429ea997a2c1d221dce8494786ff22fe35b3ee086674f2f9b89814b30")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "35p3H79foYUXBKGjm6ux2pFReiHHbkWszu"


def test_get_wallet_address_sh_wit(cmd):
    # test for a wrapped segwit wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            "[61e4f658]xpub6Dk2M8SzqzeRyuYuSJ1Vy5uRBvKfV7625LoME3KsDYRuEL8dww4MSQWMEkLLuJF9UK86hZUtRmqx1LSd1c6boq24dyq4E8UEPypQsSxupQ2",
            "[acc1fe38]xpub6EZ2Bt4cGEhrYbtgzPgZjaC9c8v5edBRYPXHZhNux5muupbeygXB8WnJg9W9nCPRQQJSwPCTJznsmygJ94ojRYgnFPQFP4Zu4TJxz1adFXy",
            "[ba16e65d]xpub6DqTtMuqBiBsHirAP1Tfm7w6ASuGqWTpn9A7efDwmYZd5bMfCuxtmBgMmVufK49sKpXgyxMhb7jYwMDa6nSzRjWry5xgDzjqrDxDqcPteqo"
        ]
    )
    wallet_sig = bytes.fromhex("30440220477d2e97a29b31691582053990b3f2215ed8ac6798b45f01f3edf60202255caa0220438bc066fa314dcb68b986398d5143caa019505e5f336e6a466df4ee3d01e01f")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "3H9iJzyiN996WcfojAmnxbFcbguBBzSSBQ"


def test_get_wallet_address_wit(cmd):
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
    wallet_sig = bytes.fromhex("3045022100de636b9241913d357fd65998054184d5bfcad2d84e5e2a9c80684086de49769f022029361b76bbd9a8684b3731afdb87141def1f138bb085bb9891156efd29c7dc47")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "bc1qj9y4fj9vq50qkr8xg3lz6tzvj53t87n36d095z2v6fp98zmedw3sakcau0"

