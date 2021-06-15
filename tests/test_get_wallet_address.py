from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet
from bitcoin_client.common import AddressType

from utils import automation
from typing import List

import pytest


def test_get_wallet_address_legacy(cmd):
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
    wallet_sig = bytes.fromhex("304502210097f74242cb29540e77c1ef52ac9daa6b6bda80ec6f3851db2061345d3cbf44f402206630675c8c20491beb1ae090e8b32508899215a21ba6b92389598d84c2a08812")

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
    wallet_sig = bytes.fromhex("304402202a0bacd2d28b8c05938cef721b30341ac9a40f48a081415df9099a19af11c33e02203e9ca45976a5c38517aec49878d8566b2acfe196f6e372ee390288020bf1f1d3")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "2MxAUTJh27foYtyp9dcSxP7RgaSwkkVCHTU"


def test_get_wallet_address_wit(cmd):
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
    wallet_sig = bytes.fromhex("304502210090e90ad5940e919cd1db5cfdac8190e1c28385d29aeda19f6de7e3d81d9b9f6d0220706051aa04a707f73608247ca2ec8c1af66b3aea3474e85d66912da87c835248")

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "tb1qmyauyzn08cduzdqweexgna2spwd0rndj55fsrkefry2cpuyt4cpsn2pg28"
