# Tests using the V1 version of the wallet policy language, used before version 2.1.0 of the app
# Make sure we remain compatible for some time.

from bitcoin_client.ledger_bitcoin import Client, AddressType, MultisigWallet, WalletPolicy, WalletType
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError
from speculos.client import SpeculosClient

import threading

import pytest

# TODO: add more tests with UI


def test_get_wallet_address_singlesig_legacy_v1(client: Client):
    # legacy address (P2PKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="pkh(@0)",
        keys_info=[
            f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "myFCUBRCKFjV7292HnZtiHqMzzHrApobpT"


def test_get_wallet_address_singlesig_wit_v1(client: Client):
    # bech32 address (P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="wpkh(@0)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "tb1qlrvzyx8jcjfj2xuy69du9trtxnsvjuped7e289"


def test_get_wallet_address_singlesig_sh_wit_v1(client: Client):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="sh(wpkh(@0))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "2NAbM4FSeBQG4o85kbXw2YNfKypcnEZS9MR"


def test_get_wallet_address_singlesig_taproot_v1(client: Client):
    # test for a native taproot wallet (bech32m addresses, per BIP-0086)

    wallet = WalletPolicy(
        name="",
        descriptor_template="tr(@0)",
        keys_info=[
            f"[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    res = client.get_wallet_address(wallet, None, 0, 0, False)
    assert res == "tb1pws8wvnj99ca6acf8kq7pjk7vyxknah0d9mexckh5s0vu2ccy68js9am6u7"

    res = client.get_wallet_address(wallet, None, 0, 9, False)
    assert res == "tb1psl7eyk2jyjzq6evqvan854fts7a5j65rth25yqahkd2a765yvj0qggs5ne"

    res = client.get_wallet_address(wallet, None, 1, 0, False)
    assert res == "tb1pmr60r5vfjmdkrwcu4a2z8h39mzs7a6wf2rfhuml6qgcp940x9cxs7t9pdy"

    res = client.get_wallet_address(wallet, None, 1, 9, False)
    assert res == "tb1p98d6s9jkf0la8ras4nnm72zme5r03fexn29e3pgz4qksdy84ndpqgjak72"


# Failure cases for default wallets

def test_get_wallet_address_default_fail_wrongkeys_v1(client: Client):
    # 0 keys info should be rejected
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[],
            version=WalletType.WALLET_POLICY_V1
        ), None, 0,  0, False)

    # more than 1 key should be rejected
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[
                f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
                f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**"
            ],
        ), None, 0,  0, False)

    # wrong BIP44 purpose should be rejected (here using 84' for a P2PKH address)
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[
                f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
            ],
            version=WalletType.WALLET_POLICY_V1
        ), None, 0,  0, False)

    # mismatching pubkey (claiming key origin "44'/1'/0'", but that's the extended dpubkey for "84'/1'/0'"")
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[
                f"[f5acc2fd/44'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**",
            ],
        ), None, 0,  0, False)

    # wrong master fingerprint
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[
                f"[42424242/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
            ],
            version=WalletType.WALLET_POLICY_V1
        ), None, 0,  0, False)

    # too large address_index, cannot be done non-silently
    with pytest.raises(IncorrectDataError):
        client.get_wallet_address(WalletPolicy(
            name="",
            descriptor_template="pkh(@0)",
            keys_info=[
                f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
            ],
            version=WalletType.WALLET_POLICY_V1
        ), None, 0,  100000, False)


# Multisig

def test_get_wallet_address_multisig_legacy_v1(client: Client):
    # test for a legacy p2sh multisig wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    wallet_hmac = bytes.fromhex(
        "1980a07cde99fbdec0d487671d3bb296507e47b3ddfa778600a9d73d501983bc"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "2Mx69MjHC4ViZAH1koVXPvVgaazbBCdr89j"


def test_get_wallet_address_multisig_sh_wit_v1(client: Client):
    # test for a wrapped segwit multisig wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    wallet_hmac = bytes.fromhex(
        "ff96c09cfacf89f836ded409b7315b9d7f242db8033e4de4db1cb4c275153988"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "2MxAUTJh27foYtyp9dcSxP7RgaSwkkVCHTU"


def test_get_wallet_address_multisig_wit_v1(client: Client):
    # test for a native segwit multisig wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    wallet_hmac = bytes.fromhex(
        "d6434852fb3caa7edbd1165084968f1691444b3cfc10cf1e431acbbc7f48451f"
    )

    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, False)
    assert res == "tb1qmyauyzn08cduzdqweexgna2spwd0rndj55fsrkefry2cpuyt4cpsn2pg28"


def test_get_wallet_address_singlesig_legacy_v1_ui(client: Client, comm: SpeculosClient,
                                                   is_speculos: bool, model: str):
    # legacy address (P2PKH)
    def ux_thread():
        event = comm.wait_for_text_event("Address")

        # press right until the last screen (will press the "right" button more times than needed)
        while "Reject" != event["text"]:
            comm.press_and_release("right")

            event = comm.get_next_event()

        # go back to the Accept screen, then accept
        comm.press_and_release("left")
        comm.press_and_release("both")

    def ux_thread_stax():
        while True:
            event = comm.get_next_event()
            if "Tap to continue" in event["text"] or "Show as QR" in event["text"]:
                comm.finger_touch(55, 550)
            elif "VERIFIED" in event["text"]:
                break

    if model == "stax":
        x = threading.Thread(target=ux_thread_stax)
    else:
        x = threading.Thread(target=ux_thread)

    wallet = WalletPolicy(
        name="",
        descriptor_template="pkh(@0)",
        keys_info=[
            f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    x.start()
    assert client.get_wallet_address(wallet, None, 0,  0, True) == "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm"
    x.join()

    if model == "stax":
        x = threading.Thread(target=ux_thread_stax)
    else:
        x = threading.Thread(target=ux_thread)
    x.start()
    assert client.get_wallet_address(wallet, None, 1, 15, True) == "myFCUBRCKFjV7292HnZtiHqMzzHrApobpT"
    x.join()


def test_get_wallet_address_multisig_legacy_v1_ui(client: Client, comm: SpeculosClient, is_speculos:
                                                  bool, model: str):
    # test for a legacy p2sh multisig wallet

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )
    wallet_hmac = bytes.fromhex(
        "1980a07cde99fbdec0d487671d3bb296507e47b3ddfa778600a9d73d501983bc"
    )

    def ux_thread():
        event = comm.wait_for_text_event("Receive")

        # press right until the last screen (will press the "right" button more times than needed)
        while "Reject" != event["text"]:
            comm.press_and_release("right")

            event = comm.get_next_event()

        # go back to the Accept screen, then accept
        comm.press_and_release("left")
        comm.press_and_release("both")

    def ux_thread_stax():
        while True:
            event = comm.get_next_event()
            if "Tap to continue" in event["text"] or "Confirm" in event["text"]:
                comm.finger_touch(55, 550)
            elif "CONFIRMED" in event["text"]:
                break

    if model == "stax":
        x = threading.Thread(target=ux_thread_stax)
    else:
        x = threading.Thread(target=ux_thread)

    x.start()
    res = client.get_wallet_address(wallet, wallet_hmac, 0, 0, True)
    x.join()
    assert res == "2Mx69MjHC4ViZAH1koVXPvVgaazbBCdr89j"
