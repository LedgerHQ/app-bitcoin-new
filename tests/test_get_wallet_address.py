from bitcoin_client.command import BitcoinCommand
from bitcoin_client.common import AddressType
from bitcoin_client.wallet import MultisigWallet

from .utils import automation

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
            f"[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm/**",
        ],
    )
    wallet_sig = bytes.fromhex(
        "3045022100814ed5cdb80ea73bb35b824150c05b5315679f62522a41e8ae66deb7467d0d2d0220229b818504314837e1f0bc06a03de35fd56e6d543cf67854d967e06c1c0f47e6"
    )

    print(wallet.policy_map)

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    print(res)
    assert res == "2Mx69MjHC4ViZAH1koVXPvVgaazbBCdr89j"


def test_get_wallet_address_sh_wit(cmd):
    # test for a wrapped segwit wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
        ],
    )
    wallet_sig = bytes.fromhex(
        "3045022100b2808b37a3a493a77432b45471dc6e1b9aed236cf3c589e6dae8b0c85d6e9e8d02203119e905dfb037433512b19185bf0e07b86ce569d5c8852d36ac6f0182f369d5"
    )

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
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
    )
    wallet_sig = bytes.fromhex(
        "30440220564c14c281594221a3309b5acd11a427a32b9fc85b8d883564004f325fb0071b02201404316adb5127b7918ecf48e3ebceea41963898b26a4643e834baa0c72a5ea2"
    )

    res = cmd.get_wallet_address(wallet, wallet_sig, 0)
    assert res == "tb1qmyauyzn08cduzdqweexgna2spwd0rndj55fsrkefry2cpuyt4cpsn2pg28"
