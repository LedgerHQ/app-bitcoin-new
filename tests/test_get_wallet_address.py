from bitcoin_client.command import BitcoinCommand
from bitcoin_client.common import AddressType
from bitcoin_client.wallet import MultisigWallet

from utils import automation
from typing import List

import pytest

# TODO: add tests with UI
# TODO: UI does not currently work


def test_get_wallet_address_legacy(cmd: BitcoinCommand):
    # test for a legacy p2sh wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/0']tpubDE7NQymr4AFtZwx94XxPNFpTduLxQB4JhTFC52AC213kND6dahQ6eznZeWcsZ5wEgZ2cVrZqdEWDB6Tvt82BYEmaia8pgFJGAj9ijtSfbxD/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**"
        ]
    )
    wallet_sig = bytes.fromhex(
        "3045022100f13adb6acd4bf8c4ce679ee2d491aad8493f23f73745feab4b2cb587add3ee43022018f585080fb6b455dacea9d34053f5dcd40a9a9ac75c86ef15262bda8361dcd9")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    print(res)
    assert res == "2N5wnrGZ99eGEvULVwXMCVUTbQ4RvocG4nU"


def test_get_wallet_address_sh_wit(cmd):
    # test for a wrapped segwit wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**"
        ]
    )
    wallet_sig = bytes.fromhex(
        "3045022100b2808b37a3a493a77432b45471dc6e1b9aed236cf3c589e6dae8b0c85d6e9e8d02203119e905dfb037433512b19185bf0e07b86ce569d5c8852d36ac6f0182f369d5")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "2MxAUTJh27foYtyp9dcSxP7RgaSwkkVCHTU"


def test_get_wallet_address_wit(cmd: BitcoinCommand):
    # test for a native segwit wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**"
        ]
    )
    wallet_sig = bytes.fromhex(
        "30440220564c14c281594221a3309b5acd11a427a32b9fc85b8d883564004f325fb0071b02201404316adb5127b7918ecf48e3ebceea41963898b26a4643e834baa0c72a5ea2")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "tb1qmyauyzn08cduzdqweexgna2spwd0rndj55fsrkefry2cpuyt4cpsn2pg28"
