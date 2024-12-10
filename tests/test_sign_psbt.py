import base64
import pytest

from pathlib import Path

from ledger_bitcoin import WalletPolicy, MultisigWallet, AddressType, PartialSignature
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException

from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import AddressType
from ragger.navigator import Navigator
from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware

from test_utils import bip0340, txmaker

from ragger_bitcoin import RaggerClient
from .instructions import *

tests_root: Path = Path(__file__).parent


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


def test_sign_psbt_singlesig_pkh_1to1(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # PSBT for a legacy 1-input 1-output spend (no change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = WalletPolicy(
        "",
        "pkh(@0/**)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
    #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    print(result)
    print([(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"),
            signature=bytes.fromhex(
                "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
            )
        )
    )])
    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"),
            signature=bytes.fromhex(
                "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
            )
        )
    )]


def test_sign_psbt_singlesig_sh_wpkh_1to2(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "sh(wpkh(@0/**))",
        [
            "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67"),
            signature=bytes.fromhex(
                "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
            )
        )
    )]


def test_sign_psbt_highfee(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Transactions with fees higher than 10% of total amount
    # An additional warning is shown.

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    # Make sure that the fees are at least 10% of the total amount
    for out in psbt.tx.vout:
        out.nValue = int(out.nValue * 0.9)

    # the test is only interesting if the total amount is at least 100000 sats
    assert sum(input.witness_utxo.nValue for input in psbt.inputs) >= 100000

    wallet = WalletPolicy(
        "",
        "sh(wpkh(@0/**))",
        [
            "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_feewarning=True),
                              testname=test_name)

    assert len(result) == 1


def test_sign_psbt_singlesig_wpkh_1to2(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    # PSBT for a segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068"),
            signature=bytes.fromhex(
                "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"
            )
        )
    )]


def test_sign_psbt_singlesig_wpkh_2to2(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    # PSBT for a segwit 2-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3"),
            signature=bytes.fromhex(
                "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
            )
        )
    ), (
        1,
        PartialSignature(
            pubkey=bytes.fromhex("0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0"),
            signature=bytes.fromhex(
                "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
            ),
        )
    )]


def test_sign_psbt_singlesig_wpkh_2to2_missing_nonwitnessutxo(navigator: Navigator, firmware:
                                                              Firmware, client: RaggerClient, test_name: str):
    # Same as the previous test, but the non-witness-utxo is missing.
    # The app should sign after a warning.

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    # remove the non-witness-utxo field
    for input in psbt.inputs:
        input.non_witness_utxo = None

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_unverifiedwarning=True),
                              testname=test_name)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3"),
            signature=bytes.fromhex(
                "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
            )
        )
    ), (
        1,
        PartialSignature(
            pubkey=bytes.fromhex("0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0"),
            signature=bytes.fromhex(
                "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
            )
        )
    )]


def test_sign_psbt_singlesig_wpkh_selftransfer(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str):

    # The only output is a change output.
    # A "self-transfer" screen should be shown before the fees.

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt = "cHNidP8BAHECAAAAAfcDVJxLN1tzz5vaIy2onFL/ht/OqwKm2jEWGwMNDE/cAQAAAAD9////As0qAAAAAAAAFgAUJfcXOL7SoYGoDC1n6egGa0OTD9/mtgEAAAAAABYAFDXG4N1tPISxa6iF3Kc6yGPQtZPsTTQlAAABAPYCAAAAAAEBCOcYS1aMP1uQcUKTMJbvlsZXsV4yNnVxynyMfxSX//UAAAAAFxYAFGEWho6AN6qeux0gU3BSWnK+Dw4D/f///wKfJwEAAAAAABepFG1IUtrzpUCfdyFtu46j1ZIxLX7ph0DiAQAAAAAAFgAU4e5IJz0XxNe96ANYDugMQ34E0/cCRzBEAiB1b84pX0QaOUrvCdDxKeB+idM6wYKTLGmqnUU/tL8/lQIgbSinpq4jBlo+SIGyh8XNVrWAeMlKBNmoLenKOBugKzcBIQKXsd8NwO+9naIfeI3nkgYjg6g3QZarGTRDs7SNVZfGPJBJJAABAR9A4gEAAAAAABYAFOHuSCc9F8TXvegDWA7oDEN+BNP3IgYCgffBheEUZI8iAFFfv7b+HNM7j4jolv6lj5/n3j68h3kY9azC/VQAAIABAACAAAAAgAAAAAAHAAAAACICAzQZjNnkwXFEhm1F6oC2nk1ADqH6t/RHBAOblLA4tV5BGPWswv1UAACAAQAAgAAAAIABAAAAEgAAAAAiAgJxtbd5rYcIOFh3l7z28MeuxavnanCdck9I0uJs+HTwoBj1rML9VAAAgAEAAIAAAACAAQAAAAAAAAAA"
    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve_selftransfer(firmware),
                              testname=test_name)

    assert len(result) == 1


# def test_sign_psbt_legacy(client: RaggerClient, test_name: str):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUhIh4AAAA="

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = client.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_legacy_p2pkh(client: RaggerClient, test_name: str):
#     # test from app-bitcoin

#     # legacy address
#     # PSBT for a legacy 1-input, 1-output + 1-change address spend
#     unsigned_raw_psbt_base64 = 'cHNidP8BAHcBAAAAAVf4kTUeYOlEcY8d8StPd7ZCzGMUYYS+3Gx7xkoMCzneAAAAAAAAAAAAAqCGAQAAAAAAGXapFHrmeHmDxejS4X7xcPdZBWw2A6fYiKygfAEAAAAAABl2qRQYm4Or/V0O+Y+/NZTJXMU7RJdK6oisAAAAAAABAOICAAAAAV33ueIMUtHaJwGiRKSXVCFSZvAW9r139kClIAzR+340AQAAAGtIMEUCIQDIBpV0KZNcXWH1SCI8NTbcc5/jUYFLzp7cFpTlpcJavwIgE+MHsLSIWstkzP+vX0eU8gUEAyXrw2wlh4fEiLA4wrsBIQOLpGLX3WWRfs5FQUKQO7NioLQS0YQdUgh62IFka2zcz/3///8CFAwDAAAAAAAZdqkUs+F8Te+KORSO1vrX3G/r4w3TJMuIrDBXBQAAAAAAGXapFOCok4BjXxi37glUbZYyMry5kkEriKz+BB0AAQMEAQAAAAAAAA=='

#     # expected sig: 3044022012f6a643d1d1a558912e0935dbd6a9694fe87c841e0f699c7cbb7c818503c115022064585f9b69c3452183a74ee7f00ae0452139e2c73b156dfd6ac835bea4fdf975

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = client.sign_psbt(psbt)

#     print(result)


def test_sign_psbt_multisig_wsh(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    wallet_hmac = bytes.fromhex(
        "d7c7a60b4ab4a14c1bf8901ba627d72140b2fb907f2b4e35d2e693bce9fbb371"
    )

    psbt = open_psbt_from_file(f"{tests_root}/psbt/multisig/wsh-2of2.psbt")

    # fees don't fit in the same page on 'flex', but they fit on 'stax'
    fees_on_next_page = firmware.name == 'flex'

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True, fees_on_next_page=fees_on_next_page),
                              testname=test_name)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("036b16e8c1f979fa4cc0f05b6a300affff941459b6f20de77de55b0160ef8e4cac"),
            signature=bytes.fromhex(
                "304402206ab297c83ab66e573723892061d827c5ac0150e2044fed7ed34742fedbcfb26e0220319cdf4eaddff63fc308cdf53e225ea034024ef96de03fd0939b6deeea1e8bd301"
            )
        )
    )]


def test_sign_psbt_multisig_sh_wsh(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # wrapped segwit multisig ("sh(wsh(sortedmulti(...)))")
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            "[e24243b4/48'/1'/0'/1']tpubDFY2NoEHyYsp4J98UCMAaRT5LzRYeXjWqh2txK2RsxPAR5YWKWyTeZBBncRJ7z5nL5RUQPEgycbgbbmywbeLaH9yWK6rnFAYQn28HyiYc1Y",
            "[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
        ],
        sorted=True
    )

    wallet_hmac = bytes.fromhex(
        "677ec94c2e1a7446c6cac9db2adde8667b9a746dd63fa1e1863553cdb814a54a"
    )

    psbt = "cHNidP8BAFUCAAAAAS60cHn6kIlm2wk314ZKiOok2xj++cPoa/K5TXzNk4s6AQAAAAD9////AescAAAAAAAAGXapFFnK2lAxTIKeGfWneG+O4NSYf0KdiKwhlRUAAAEAigIAAAABAaNw+E0toKUlohxkK0YmapPS7uToo7RG7DA2YLrmoD8BAAAAFxYAFAppBymwQTPq8lpFfFWMuPRNdbTX/v///wI7rUIBAAAAABepFJMyNbbbdF4o3zxQhWSJ5ZXY5naHh60dAAAAAAAAF6kU9wt/XvakFsqnsR6xlBxP5N9MyyqHbvokAAEBIK0dAAAAAAAAF6kU9wt/XvakFsqnsR6xlBxP5N9MyyqHAQQiACAyIOGl/sIPCRep2F4Bude0ME17U2m2dPAiK96XdDCf7wEFR1IhA0fxhNV0BDkMTLzQjBSpKxSeh39pMEcQ+reqlD2a/D20IQPlOZCX7JMMMjUxBLMNtzR+gcVKZaL4J4sf/VRbo03NfFKuIgYDR/GE1XQEOQxMvNCMFKkrFJ6Hf2kwRxD6t6qUPZr8PbQc4kJDtDAAAIABAACAAAAAgAEAAIAAAAAAAAAAACIGA+U5kJfskwwyNTEEsw23NH6BxUplovgnix/9VFujTc18HPWswv0wAACAAQAAgAAAAIABAACAAAAAAAAAAAAAAA=="
    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True),
                              testname=test_name)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03e5399097ec930c32353104b30db7347e81c54a65a2f8278b1ffd545ba34dcd7c"),
            signature=bytes.fromhex(
                "30440220689c3ee23b8f52c21abe47ea6f37cf8bc72653cab9cd32658199b1a16db193d802200db5d2157044913d5a60f69e9ce10ab9a9d883d421d3fb0400d948b31c3b7ee201"
            )
        )
    )]


def test_sign_psbt_multisig_sh_wsh_missing_nonwitnessutxo(navigator: Navigator, firmware: Firmware,
                                                          client: RaggerClient, test_name: str):
    # A transaction spending a wrapped segwit address has a script that appears like a legacy UTXO, but uses
    # the segwit sighash algorithm.
    # Therefore, if the non-witness-utxo is missing, we should still sign it while giving the warning for unverified inputs,
    # for consistency with other segwit input types.

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            "[e24243b4/48'/1'/0'/1']tpubDFY2NoEHyYsp4J98UCMAaRT5LzRYeXjWqh2txK2RsxPAR5YWKWyTeZBBncRJ7z5nL5RUQPEgycbgbbmywbeLaH9yWK6rnFAYQn28HyiYc1Y",
            "[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
        ],
        sorted=True
    )

    wallet_hmac = bytes.fromhex(
        "677ec94c2e1a7446c6cac9db2adde8667b9a746dd63fa1e1863553cdb814a54a"
    )

    psbt = "cHNidP8BAFUCAAAAAS60cHn6kIlm2wk314ZKiOok2xj++cPoa/K5TXzNk4s6AQAAAAD9////AescAAAAAAAAGXapFFnK2lAxTIKeGfWneG+O4NSYf0KdiKwhlRUAAAEBIK0dAAAAAAAAF6kU9wt/XvakFsqnsR6xlBxP5N9MyyqHAQQiACAyIOGl/sIPCRep2F4Bude0ME17U2m2dPAiK96XdDCf7wEFR1IhA0fxhNV0BDkMTLzQjBSpKxSeh39pMEcQ+reqlD2a/D20IQPlOZCX7JMMMjUxBLMNtzR+gcVKZaL4J4sf/VRbo03NfFKuIgYDR/GE1XQEOQxMvNCMFKkrFJ6Hf2kwRxD6t6qUPZr8PbQc4kJDtDAAAIABAACAAAAAgAEAAIAAAAAAAAAAACIGA+U5kJfskwwyNTEEsw23NH6BxUplovgnix/9VFujTc18HPWswv0wAACAAQAAgAAAAIABAACAAAAAAAAAAAAAAA=="
    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True, has_unverifiedwarning=True),
                              testname=test_name)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03e5399097ec930c32353104b30db7347e81c54a65a2f8278b1ffd545ba34dcd7c"),
            signature=bytes.fromhex(
                "30440220689c3ee23b8f52c21abe47ea6f37cf8bc72653cab9cd32658199b1a16db193d802200db5d2157044913d5a60f69e9ce10ab9a9d883d421d3fb0400d948b31c3b7ee201"
            )
        )
    )]


def test_sign_psbt_taproot_1to2_sighash_all(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):

    # PSBT for a p2tr 1-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/tr-1to2-sighash-all.psbt")

    wallet = WalletPolicy(
        "",
        "tr(@0/**)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware),
                              testname=test_name)
    assert len(result) == 1

    # Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
    # Therefore, for this testcase we hard-code the sighash (which was validated with Bitcoin Core 22.0 when the
    # transaction was sent), and we verify the produced Schnorr signature with the reference bip340 implementation.

    # sighash verified with bitcoin-core
    sighash0 = bytes.fromhex("7A999E5AD6F53EA6448E7026061D3B4523F957999C430A5A492DFACE74AE31B6")

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0_psbt = psbt.inputs[0].witness_utxo.scriptPubKey[2:]

    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    assert partial_sig0.pubkey == pubkey0_psbt
    assert partial_sig0.tapleaf_hash is None

    # the sighash 0x01 is appended to the signature
    assert len(partial_sig0.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x01

    assert bip0340.schnorr_verify(sighash0, pubkey0_psbt, partial_sig0.signature[:-1])


def test_sign_psbt_taproot_1to2_sighash_default(navigator: Navigator, firmware: Firmware, client:
                                                RaggerClient, test_name: str):

    # PSBT for a p2tr 1-input 2-output spend (1 change address)

    # Test two times:
    # - the first PSBT has SIGHASH_DEFAULT;
    # - the second PSBT does not specify the sighash type.
    # The behavior for taproot transactions should be the same, producing 64-byte signatures

    index = 0
    for psbt_file_name in ["tr-1to2-sighash-default", "tr-1to2-sighash-omitted"]:
        psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/{psbt_file_name}.psbt")

        wallet = WalletPolicy(
            "",
            "tr(@0/**)",
            [
                "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
            ],
        )

        result = client.sign_psbt(psbt, wallet, None, navigator,
                                  instructions=sign_psbt_instruction_approve(firmware),
                                  testname=f"{test_name}_{index}")
        index += 1

        # Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
        # Therefore, for this testcase we hard-code the sighash (which was validated with Bitcoin Core 22.0 when the
        # transaction was sent), and we verify the produced Schnorr signature with the reference bip340 implementation.

        # sighash verified with bitcoin-core
        sighash0 = bytes.fromhex("75C96FB06A12DB4CD011D8C95A5995DB758A4F2837A22F30F0F579619A4466F3")

        # get the (tweaked) pubkey from the scriptPubKey
        expected_pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]

        assert len(result) == 1

        idx0, partial_sig0 = result[0]

        assert idx0 == 0
        assert partial_sig0.pubkey == expected_pubkey0
        assert len(partial_sig0.signature) == 64
        assert partial_sig0.tapleaf_hash is None

        assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature)


def test_sign_psbt_singlesig_wpkh_4to3(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    # PSBT for a segwit 4-input 3-output spend (1 change address)
    # this test also checks that addresses, amounts and fees shown on screen are correct

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    n_ins = 4
    n_outs = 3

    in_amounts = [10000 + 10000 * i for i in range(n_ins)]
    total_in = sum(in_amounts)
    out_amounts = [total_in // n_outs - i for i in range(n_outs)]

    change_index = 1

    psbt = txmaker.createPsbt(
        wallet,
        in_amounts,
        out_amounts,
        [i == change_index for i in range(n_outs)]
    )

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve_streaming(firmware, output_count=2, save_screenshot=False),
                              testname=test_name)

    assert len(result) == n_ins


def test_sign_psbt_singlesig_large_amount(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str):
    # Test with a transaction with an extremely large amount

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt = "cHNidP8BAF4BAAAAAdPD2ZYMl89dk/YzXHTZhrjEqcvlBkVYNrcVY7772qITAAAAAAAAAAAAAWC5BVrwdQcAIlEgxg2/6wYrgIO8mjVxHIi7Ulp5V3e27qVz+FL9IxOy09oAAAAAAAEA/TIEAgAAAAclqfEztd6haPTihR8HL8wA/Kp8piBhcXpI5S4po/o3mhEAAABQlT+qaJPjLsWie5ReYF8QhfMjLUJMEynIjXhu1ozm/LYqpjv5q2F8CIo7cL5XqtofM0pwFyUNP2A9yC69OxILY14/9WsfC9kzhSNxJJqz31wAAAAAH+8UM8hmhbfwVmgdUVKvgDziWQbx0Z+2xoBOBuooqxcRAAAAUI9Feva0k7dDnsbUKQBiq1F6cuXB1BDN1hdU5CCEUOT5ABP9pp/vGdRgKkIHzdWhAW0HATJhPGWaj10z88spC4znO4NEsTpPjgkVFGmEobsVAAAAAP3q3r5basCVBEZNiqqsvC+tEhWKU0yUuMpCljr0ehidBQAAAFAkms6omdQ3MvbyrK8/9Tv+2hOaq09VwCwhK2VxH8UEMsmU5fpv2Cq8cIVV3GK3OiAO52c8/suDahVuSjVl6sG5TTX5S8/Y/aX//2dwBK6ipAAAAAASS4NPwpbwISsUIXNCFJkH5alSTOu+wxEuJ9pplNX2xhMAAABQdwoAXZqCqiH8hpvQxMQfU0F6kqscEvbVSPspTbTSEu7F6hgz8U0KEEOlNbFjxPs4Hu+sP5dBxpY+YBPI475h6bYmFhT4gg1udS/XnDpK2tgAAAAAKzXUIDLUTw/k3NUP/qaBKLQkPrcPsLJbBXa7JElqAWgDAAAAUAOWvAx3SF/oOfSwhEIOarmr8pWXp14pNJ1QwEtAcqF8eV6VvtYXQwrJJyVD15nVSNiYtSt/470dwNEE1aThaL6W8S5eN405TuTMXtfdWX7oAAAAAK5Itews92iWAOXsA2+YOppP2fEv/nbPjws9ihQAg8vKDgAAAFA0gbWRZCsSJIacrjx/UyLUlJBEazXSzo6V4r5GUD89w83vR5m18tRv9Pqi/B7jmUn9Gm4NtfHIBSIpygO4FTsBipV0SJNhNd7rqcRWqdfeSwAAAADlS6FCal/jssfa+8dwZOBoGcYRdytfuh1Yd5gskbTS6gEAAABQ3Oj6gvNurIgVFhpTswGUA0cg23HLcehirTQro6XppoIOFmG8KWuxYGeAmp/EgvawehacJQTr/eAY0/zr4TwrKXsyTtNt4SfayRRcf/pwQY4AAAAABwBAB1rwdQcAFgAU0+7eJu+wC1UvKNIxz4CFDRczm/I4L20CAAAAABYAFPNyGL5lUjRibFPLi01BEjsLwASNM8SqBAAAAAAWABSuAZ+UnYYxIwc3Aj30hZG6rKwna4g7HQEAAAAAFgAUKKpV9FUdnX0XjRKi5566B7GilM6hNsIAAAAAABYAFPUxxs1RBp+b5Rgv3WHXHbJgLZ/uWTGkBQAAAAAWABRFAR8Q58ACMpSpRHc+W/AYljP3EW9EygAAAAAAFgAU25qB3Gwdk2er+8rT9SF8FAc+bfEAAAAAAQEfAEAHWvB1BwAWABTT7t4m77ALVS8o0jHPgIUNFzOb8iIGA5NNbsxZ4ylv9Q0vs4yPSxu05hJFFW48jPoNtiyScnRJGPWswv1UAACAAQAAgAAAAIABAAAAuCAAAAAA"

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware),
                              testname=test_name)

    assert len(result) == 1


def test_sign_psbt_singlesig_wpkh_512to256(navigator: Navigator, firmware: Firmware, client:
                                           RaggerClient, test_name: str, enable_slow_tests: bool):
    # PSBT for a transaction with 512 inputs and 256 outputs (maximum currently supported in the app)
    # Very slow test (esp. with DEBUG enabled), so disabled unless the --enableslowtests option is used

    if not enable_slow_tests:
        pytest.skip()

    wallet = WalletPolicy(
        "",
        "tr(@0/**)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
        ],
    )

    n_inputs = 512
    n_outputs = 256

    input_amounts = [10000 + 10000 * i for i in range(n_inputs)]
    total_amount = sum(input_amounts)
    output_amounts = [(total_amount // n_outputs) - 10 for _ in range(n_outputs)]

    psbt = txmaker.createPsbt(
        wallet,
        input_amounts,
        output_amounts,
        [i == 42 for i in range(n_outputs)]
    )

    result = client.sign_psbt(psbt, wallet, None, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False),
                              testname=test_name)

    assert len(result) == n_inputs


def test_sign_psbt_fail_11_changes(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # PSBT for transaction with 11 change addresses; the limit is 10, so it must fail with NotSupportedError
    # before any user interaction on nanos.

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt = txmaker.createPsbt(
        wallet,
        [11 * 100_000_000 + 1234],
        [100_000_000] * 11,
        [True] * 11,
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet, None, navigator,
                         instructions=sign_psbt_instruction_tap(firmware),
                         testname=test_name)

    assert DeviceException.exc.get(e.value.status) == NotSupportedError

    # defined in error_codes.h
    EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS = 0x0009

    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_TOO_MANY_CHANGE_OUTPUTS


def test_sign_psbt_fail_wrong_non_witness_utxo(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str):
    # PSBT for transaction with the wrong non-witness utxo for an input.
    # It must fail with IncorrectDataError before any user interaction.

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt = txmaker.createPsbt(
        wallet,
        [3 * 100_000_000],
        [1 * 100_000_000, 2 * 100_000_000],
        [False, True]
    )

    # Modify the non_witness_utxo so that the txid does not matches
    wit = psbt.inputs[0].non_witness_utxo
    wit.nLockTime = wit.nLockTime ^ 1  # change one bit of nLockTime arbitrarily to change the txid
    wit.rehash()
    psbt.inputs[0].non_witness_utxo = wit

    client._no_clone_psbt = True
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_psbt(psbt, wallet, None, navigator,
                         instructions=sign_psbt_instruction_approve(firmware, save_screenshot=False),
                         testname=test_name)
    client._no_clone_psbt = False

    assert DeviceException.exc.get(e.value.status) == IncorrectDataError

    # defined in error_codes.h
    EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED = 0x0004

    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_SIGN_PSBT_NONWITNESSUTXO_CHECK_FAILED




def test_sign_psbt_with_opreturn(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt_b64 = "cHNidP8BAKMCAAAAAZ0gZDu3l28lrZWbtsuoIfI07zpsaXXMe6sMHHJn03LPAAAAAAD+////AgAAAAAAAAAASGpGVGhlIFRpbWVzIDAzL0phbi8yMDA5IENoYW5jZWxsb3Igb24gYnJpbmsgb2Ygc2Vjb25kIGJhaWxvdXQgZm9yIGJhbmtzLsGVmAAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ8AAAAAAAEAcQIAAAABnpp88I3RXEU5b28rI3GGAXaWkk+w1sEqWDXFXdacKg8AAAAAAP7///8CgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmvNabSkBAAAAFgAUCA6eZPSQK9gnq8ngOSaQ0ZdPeIVBAAAAAQEfgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmiIGAny3XTSwBcTrn2K78sRX12OOgT51fvzsj6aGd9lQtjZiGPWswv1UAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAA=="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    # to and amount fit on the same page on stax, but not on flex
    to_on_next_page = firmware.name == 'flex'

    hww_sigs = client.sign_psbt(psbt, wallet, None, navigator,
                                instructions=sign_psbt_instruction_approve(firmware, to_on_next_page=to_on_next_page, fees_on_next_page=True),
                                testname=test_name)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_naked_opreturn(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    # Same psbt as in test_sign_psbt_with_opreturn, but the first output is a naked OP_RETURN script (no data).
    # Signing such outputs is needed in BIP-0322.
    psbt_b64 = "cHNidP8BAFwCAAAAAZ0gZDu3l28lrZWbtsuoIfI07zpsaXXMe6sMHHJn03LPAAAAAAD+////AgAAAAAAAAAAAWrBlZgAAAAAABYAFCuTP2nl6yRKHwS+1J6OyeTsk7yfAAAAAAABAHECAAAAAZ6afPCN0VxFOW9vKyNxhgF2lpJPsNbBKlg1xV3WnCoPAAAAAAD+////AoCWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JrzWm0pAQAAABYAFAgOnmT0kCvYJ6vJ4DkmkNGXT3iFQQAAAAEBH4CWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JoiBgJ8t100sAXE659iu/LEV9djjoE+dX787I+mhnfZULY2Yhj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAACICAxmbidg1b1fhzjgKEgXPKGBtvqiYVbEcPf7PuKGlM1aJGPWswv1UAACAAQAAgAAAAIABAAAAAQAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    hww_sigs = client.sign_psbt(psbt, wallet, None, navigator,
                                instructions=sign_psbt_instruction_approve(firmware),
                                testname=test_name)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_segwit_v16(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # This psbt contains an output with future psbt version 16 (corresponding to address
    # tb1sqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4hu3px).
    # The app should accept it nonetheless.

    psbt_b64 = "cHNidP8BAH0CAAAAAZvg4s1Yxz9DddwBeI+qqU7hcldqGSgWPXuZZReEFYvKAAAAAAD+////AqdTiQAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ9AQg8AAAAAACJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAHECAAAAAYWOSCXXmA0ztidPI5A6FskW99o7nWNVeFP7rXND5B9aAAAAAAD+////AoCWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JrzWm0pAQAAABYAFF7XSHCIZoptcIrXIWce1tKqp11EaQAAAAEBH4CWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JoiBgJ8t100sAXE659iu/LEV9djjoE+dX787I+mhnfZULY2Yhj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    hww_sigs = client.sign_psbt(psbt, wallet, None, navigator,
                                instructions=sign_psbt_instruction_approve(firmware),
                                testname=test_name)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_external_inputs(navigator: Navigator, firmware: Firmware, client:
                                        RaggerClient, test_name: str):

    instructions = [sign_psbt_instruction_approve_external_inputs(firmware, output_count=5),
                    sign_psbt_instruction_approve_external_inputs(firmware, output_count=4),
                    sign_psbt_instruction_approve_external_inputs(firmware, output_count=4)]
    # PSBT obtained by joining pkh-1to1.psbt, tr-1to2.psbt, wpkh-1to2.psbt.
    # We sign it with each of the respective wallets; therefore it must show the "external inputs" warning each time.
    psbt_b64 = "cHNidP8BAP0yAQIAAAADobgj0jNtaUtJNO+bblt94XoFUT2oop2wKi7Lx6mm/m0BAAAAAP3///9RIsLN5oI+VXVBdbksnFegqOGsg8OOF4f9Oh/zNI6VEwEAAAAA/f///3oqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////BaCGAQAAAAAAFgAUE5m4oJhHoDmwNS9Y0hLBgLqxf3dV/6cAAAAAACJRIAuOdIa8MGoK77enwArwQFVC2xrNc+7MqCdxzPX+XrYPeEEPAAAAAAAZdqkUE9fVgWaUbD7AIpNAZtjA0RHRu0GIrHQ4IwAAAAAAFgAU6zj6m4Eo+B8m6V7bDF/66oNpD+Sguw0AAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAABASunhqkAAAAAACJRINj08dGJltthuxyvVCPeJdih7unJUNN+b/oCMBLV5i4NIRYhLqKFalzxEOZqK+nXNTFHk/28s4iyuPE/K2remC569RkA9azC/VYAAIABAACAAAAAgAEAAAAAAAAAARcgIS6ihWpc8RDmaivp1zUxR5P9vLOIsrjxPytq3pguevUAAQCMAgAAAAHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrITyHAAiBgLuhgggfiEChCb2nnZEfX49XgdwSfXmg8MTbCMUdipHGBj1rML9LAAAgAEAAIAAAACAAAAAAAAAAAAAAQB9AgAAAAGvv64GWQ90H/GvWbasRhEmM2pMSoLbVT32/vq3N6wz8wEAAAAA/f///wJwEQEAAAAAACIAIP3uRBxW5bBtDfgsEkxwcBSlyhlli+C5hWvKFvHtMln3pfQwAAAAAAAWABQ6+EKa1ZVKpe6KM8mD/YoehnmSSwAAAAABAR+l9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLIgYD7iw9mOsfk8Chqo5aQAm3Dre0Tq0V8WZvE2sBKtWNMGgY9azC/VQAAIABAACAAAAAgAEAAAAIAAAAAAABBSACkIHs5WFqocuZMZ/Eh07+5H8IzrpfYARjbIxDQJpfCiEHApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwoZAPWswv1WAACAAQAAgAAAAIABAAAAAgAAAAAAIgICKexHcnEx7SWIogxG7amrt9qm9J/VC6/nC5xappYcTswY9azC/VQAAIABAACAAAAAgAEAAAAKAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallets = [
        WalletPolicy(
            "",
            "pkh(@0/**)",
            [
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
            ],
        ),
        WalletPolicy(
            "",
            "tr(@0/**)",
            [
                "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
            ],
        ),
        WalletPolicy(
            "",
            "wpkh(@0/**)",
            [
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
            ],
        )
    ]

    index = 0
    for wallet, text in zip(wallets, instructions):
        hww_sigs = client.sign_psbt(psbt, wallet, None, navigator,
                                    instructions=text,
                                    testname=f"{test_name}_{index}")
        index += 1

        assert len(hww_sigs) == 1


def test_sign_psbt_miniscript_multikey(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    # An earlier (unreleased) version of the app had issues in recognizing the internal key in
    # wallets with multiple internal keys. This caused the app not to recognize some inputs as
    # internal and refuse signing.
    # This test avoid regressions.

    psbt_b64 = "cHNidP8BAH0CAAAAAc73gS9SovmC2TiOljy8430GM1piHwQ2qexyVay941KiAAAAAAD9////AoRMiQAAAAAAIgAgCNTAdTDWmzUxjznipRc1U4uQGLRoZrO78XwYXYUabZpAQg8AAAAAABYAFERtNGMisyaTdIH6qfcs0sgquVa9AAAAAAABAIkCAAAAARZzljeqA1KqIrHu0Dlk1eHOMjicZvTJNJyJr/EKGRpbAAAAAAD+////AoCWmAAAAAAAIgAg7J/0qnaRhypwlt/UpEpsEFWGdEW1xaoG8zEdfnMy+LjbWm0pAQAAACJRIDnrpLTPwAtLr+lUmuKj0BponWuHmsIjhT94mb7F0QNeaQAAAAEBK4CWmAAAAAAAIgAg7J/0qnaRhypwlt/UpEpsEFWGdEW1xaoG8zEdfnMy+LgBBY4hA1h5yhc6nBs/MA7Fh/tMxtVNYY4wWE5CXBtTuYgocI8drGQhArcwd+z8NOR+OK4rn4KGkQCCFM8COcy6P8m/T41alSKMrSED2O7HEKG8D9F+VNLOnTTQL43jAvbEPioS3GbGDIQceJVnIQMcumfE5xIqwJgWWRP5G5iLnJRWKeGzi7yANv+se/rxEmisIgYCtzB37Pw05H44riufgoaRAIIUzwI5zLo/yb9PjVqVIowY9azC/SwAAIABAACAAAAAgAIAAAADAAAAIgYDHLpnxOcSKsCYFlkT+RuYi5yUVinhs4u8gDb/rHv68RIMoPWInwAAAAADAAAAIgYDWHnKFzqcGz8wDsWH+0zG1U1hjjBYTkJcG1O5iChwjx0Y9azC/SwAAIABAACAAAAAgAAAAAADAAAAIgYD2O7HEKG8D9F+VNLOnTTQL43jAvbEPioS3GbGDIQceJUMt6EhtAAAAAADAAAAAAEBjiECUzcaIHTkAJE5L9bKuknM0NEVGMEJZh9J+AglLIn3FWSsZCECmjJ4GqB1Hs3Dr/H+FWE3rSzge5+iVTuf+FA3DBpG3SWtIQL+762PyBkOL51EV+NoTOccB+ABFJtDgCJ3I79tiEq7cGchAuWvSvOsaVtJcvo5AFkgH7RZXYD4+VU+4x4MqG2IiTPcaKwiAgJTNxogdOQAkTkv1sq6SczQ0RUYwQlmH0n4CCUsifcVZBj1rML9LAAAgAEAAIAAAACAAQAAAAEAAAAiAgKaMngaoHUezcOv8f4VYTetLOB7n6JVO5/4UDcMGkbdJRj1rML9LAAAgAEAAIAAAACAAwAAAAEAAAAiAgLlr0rzrGlbSXL6OQBZIB+0WV2A+PlVPuMeDKhtiIkz3Ayg9YifAQAAAAEAAAAiAgL+762PyBkOL51EV+NoTOccB+ABFJtDgCJ3I79tiEq7cAy3oSG0AQAAAAEAAAAAAA=="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallet = WalletPolicy(
        "Me and Bob or me and Carl",
        "wsh(c:andor(pk(@0/<0;1>/*),pk_k(@1/**),and_v(v:pk(@0/<2;3>/*),pk_k(@2/**))))",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
            "tpubDDcwGjxKph1xkiAnzvpgdnTeaEhVnH9d766yqvd16JN7EmPW9qSwnbco7kZwPd7UbyEwRojYGUaHT1UULbdqAjGQzeCy3qdZEwZLRmpzwZV",
            "tpubDCDraP1C24GGX6BHCewLBWbKQRNGACfz8JjyKXYoZjEJWeGV5Ng43FL31MryaiqeBjdC5dPUZD2zqnmMe6gqrYEstnu8pmJZYp3AQmhzQ6G",
        ]
    )

    wallet_hmac = bytes.fromhex(
        "e139a96195e18bc61e8cda72d11b3f75d3084a5c893990ca74a152206064792d"
    )

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True),
                              testname=test_name)

    assert len(result) == 2


def test_sign_psbt_singlesig_pkh_1to1_other_encodings(navigator: Navigator, firmware: Firmware,
                                                      client: RaggerClient, test_name: str):
    # same as test_sign_psbt_singlesig_pkh_1to1, but the psbt is passed as bytes or base64 string

    psbt_obj = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = WalletPolicy(
        "",
        "pkh(@0/**)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        ],
    )

    psbt_b64 = psbt_obj.serialize()
    psbt_bytes = base64.b64decode(psbt_b64)

    index = 0
    for psbt in [psbt_b64, psbt_bytes]:
        # expected sigs:
        # #0:
        #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
        #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"

        result = client.sign_psbt(psbt, wallet, None, navigator,
                                  instructions=sign_psbt_instruction_approve(firmware),
                                  testname=f"{test_name}_{index}")
        index += 1

        assert result == [(
            0,
            PartialSignature(
                pubkey=bytes.fromhex("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"),
                signature=bytes.fromhex(
                    "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
                )
            )
        )]


def test_sign_psbt_tr_script_pk_sighash_all(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    # Transaction signed with SIGHASH_ALL, therefore producing a 65-byte signature

    wallet = WalletPolicy(
        name="Taproot foreign internal key, and our script key",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    wallet_hmac = bytes.fromhex(
        "dae925660e20859ed8833025d46444483ce264fdb77e34569aabe9d590da8fb7"
    )

    psbt = PSBT()
    psbt.deserialize("cHNidP8BAFICAAAAAR/BzFdxy4OGDMVtlLz+2ThgjBf2NmJDW0HpxE/8/TFCAQAAAAD9////ATkFAAAAAAAAFgAUqo7zdMr638p2kC3bXPYcYLv9nYUAAAAAAAEBK0wGAAAAAAAAIlEg/AoQ0wjH5BtLvDZC+P2KwomFOxznVaDG0NSV8D2fLaQBAwQBAAAAIhXBUBcQi+zqje3FMAuyI4azqzA2esJi+c5eWDJuuD46IvUjIGsW6MH5efpMwPBbajAK//+UFFm28g3nfeVbAWDvjkysrMAhFlAXEIvs6o3txTALsiOGs6swNnrCYvnOXlgybrg+OiL1HQB2IjpuMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAIRZrFujB+Xn6TMDwW2owCv//lBRZtvIN533lWwFg745MrD0BCS7aAzYX4hDuf30ON4pASuocSLVqoQMCK+z3dG5HAKT1rML9MAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAARcgUBcQi+zqje3FMAuyI4azqzA2esJi+c5eWDJuuD46IvUBGCAJLtoDNhfiEO5/fQ43ikBK6hxItWqhAwIr7Pd0bkcApAAA")

    # fees don't fit in the same page on 'flex', but they fit on 'stax'
    fees_on_next_page = firmware.name == 'flex'

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True, fees_on_next_page=fees_on_next_page),
                              testname=test_name)

    assert len(result) == 1

    # sighash verified with bitcoin-core (real transaction)
    sighash0 = bytes.fromhex("39CEACF28A980B46749DD416EABE6E380C0C3742D19AA3E2ABB64F0840251E5B")

    assert len(result) == 1

    idx0, partial_sig0 = result[0]

    assert idx0 == 0
    assert partial_sig0.pubkey == bytes.fromhex("6b16e8c1f979fa4cc0f05b6a300affff941459b6f20de77de55b0160ef8e4cac")
    assert partial_sig0.tapleaf_hash == bytes.fromhex(
        "092eda033617e210ee7f7d0e378a404aea1c48b56aa103022becf7746e4700a4")

    assert len(partial_sig0.signature) == 65
    assert partial_sig0.signature[-1] == 1  # SIGHASH_ALL

    assert bip0340.schnorr_verify(sighash0, partial_sig0.pubkey, partial_sig0.signature[:64])


def test_sign_psbt_against_wrong_tapleaf_hash(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    # Versions 2.1.2, 2.1.3 and 2.2.0 incorrectly derived keys for policies with keys whose
    # derivation doesn't end in /** or /<0;1>/*.
    wallet = WalletPolicy(
        name="Used to return a wrong tapleaf_hash",
        descriptor_template="tr(@0/<0;1>/*,{and_v(v:multi_a(1,@1/<2;3>/*,@2/<2;3>/*),older(2)),multi_a(2,@1/<0;1>/*,@2/<0;1>/*)})",
        keys_info=[
            "tpubDD7LLJNCVTKQiB41FH3NyJPzMUNroRtzzY3WFAzKZDikrMpw9PJTi6A2Yes5Tamin4wsgJ4JLsj2AVUSvQqP2T6q3bztu7obRuU3Lrh4eTw",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "tpubDCczwGSwQAF9Z5gTqL3tjznCFC9De5kFBLGdJJuj3UogVyYXVG7HuFdNsvJ9oDtvn4waeawS8XvRpBfbAZaDv1pGRiZdc9qnQhLKTS8eWXH"
        ]
    )

    wallet_hmac = bytes.fromhex(
        "649d8ef6721d63046144f4f05d156655bc42fb0fe4a85020ac524cd79973c9d1")

    psbt_b64 = "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"

    # fees don't fit in the same page on 'flex', but they fit on 'stax'
    fees_on_next_page = firmware.name == 'flex'

    result = client.sign_psbt(psbt_b64, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(firmware, has_spend_from_wallet=True, fees_on_next_page=fees_on_next_page),
                              testname=test_name)

    assert len(result) == 2

    # This test assumes that keys are yielded in the same order as the internal placeholders

    part_sig_1 = result[0][1]
    assert part_sig_1.pubkey == bytes.fromhex(
        "21176cb588d36748033a66214169e13cb7928311554fbf8fd836b9ace439a1f4")
    # version 2.2.0 returned b2ee0699c6063e37ee778bd87774660b3f4c62b47473f28a0d32e6ff2bccd5db for part_sig_1.tapleaf_hash
    assert part_sig_1.tapleaf_hash == bytes.fromhex(
        "b1dd2a8bcd207330117ecaff279706fbcbcc339f1de98779a435b11284411575")

    part_sig_2 = result[1][1]
    assert part_sig_2.pubkey == bytes.fromhex(
        "9e646fb9e0452460944e49f8869f9ab9da90820da5d53841af9e1271a3bcf9ce")
    assert part_sig_2.tapleaf_hash == bytes.fromhex(
        "5b82996fe6cf1bf43868511181c64c965b7bf5f16f007acec52dede5288f9225")


def test_sign_psbt_multiple_derivation_paths(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # A previous implementation of the app incompletely checked the derivation paths of keys in certain
    # transactions when multiple internal in the policy; that wasn't detected in other tests, so this
    # was added in order to avoid regressions.
    wallet = WalletPolicy(
        name="Cold storage",
        descriptor_template="wsh(or_d(multi(4,@0/<0;1>/*,@1/<0;1>/*,@2/<0;1>/*,@3/<0;1>/*),and_v(v:thresh(3,pkh(@0/<2;3>/*),a:pkh(@1/<2;3>/*),a:pkh(@2/<2;3>/*),a:pkh(@3/<2;3>/*)),older(65535))))",
        keys_info=["[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK", 'tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF',
                   'tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh', 'tpubDD3ULTdBbyuMMMs8BCsJKgZgEnZjjbsbtV6ig3xtkQnaSc1gu9kNhmDDEW49HoLzDNA4y2TMqRzj4BugrrtcpXkjoHSoMVhJwfZLUFmv6yn']
    )
    wallet_hmac = bytes.fromhex(
        "8a0e67be3697449e4d1b19d6aaec634ce747cbcf35287887588028c9da250ab3")

    psbt_b64 = "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"
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    assert len(psbt.inputs) == 1

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_spend_from_wallet=True, save_screenshot=False),
                              testname=test_name)

    assert len(result) == 2

    # Removing all the PSBT_IN_BIP32_DERIVATION fields for that don't end in /<0;1>/*, the app should
    # no longer sign for those keys (therefore we only expect one signature)
    for input in psbt.inputs:
        for pk, key_orig in list(input.hd_keypaths.items()):
            if key_orig.path[-2] not in [0, 1]:
                del input.hd_keypaths[pk]

    result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator,
                              instructions=sign_psbt_instruction_approve(
                                  firmware, has_spend_from_wallet=True, save_screenshot=False),
                              testname=test_name)

    assert len(result) == 1
