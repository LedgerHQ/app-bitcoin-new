from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet
from bitcoin_client.common import AddressType

from utils import automation
from typing import List

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


def test_get_wallet_address_legacy(cmd):
    # test for a legacy p2sh wallet

    wallet = get_wallet(AddressType.LEGACY)
    wallet_sig = bytes.fromhex("3045022100bdb23a0fb16b96ac6fca8250ddbf70eb02a7efcc27185a172776ced25a4da693022050b513e1530ac852bf07b2d430d862a9a2adfd9669eed41ae13b45eb84a15cee")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "35p3H79foYUXBKGjm6ux2pFReiHHbkWszu"


def test_get_wallet_address_wit(cmd):
    # test for a native segwit wallet (bech32 address)

    wallet = get_wallet(AddressType.WIT)
    wallet_sig = bytes.fromhex("3045022100aeeeeaeb409f419c8a362cc1ccd3f84c559863e9b2612756424810e38bad0d6402203d797b529da758d0c5cf5a51bba470521cf3a10838e53c7936320f3aa17c64a1")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "bc1qj9y4fj9vq50qkr8xg3lz6tzvj53t87n36d095z2v6fp98zmedw3sakcau0"


def test_get_wallet_address_sh_wit(cmd):
    # test for a wrapped segwit wallet

    wallet = get_wallet(AddressType.SH_WIT)
    wallet_sig = bytes.fromhex("30440220132c93855e9c27ec20398eb7ee22db20b1cae0f472db32a1e24d9d2e3e44f7a302207ac7a3aa734bf286fabb70e8aed28fadcee59053bbc58d9ecb64bcdd46c917fc")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "3H9iJzyiN996WcfojAmnxbFcbguBBzSSBQ"
