from pathlib import Path

from bitcoin_client.command import BitcoinCommand

from bitcoin_client.psbt import PSBT
from bitcoin_client.wallet import PolicyMapWallet, MultisigWallet, AddressType

from .utils import automation

tests_root: Path = Path(__file__).parent


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


@automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_singlesig_pkh_1to1(cmd: BitcoinCommand):

    # PSBT for a legacy 1-input 1-output spend (no change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = PolicyMapWallet(
        "",
        "pkh(@0)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
    #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
    result = cmd.sign_psbt(psbt, wallet, None)

    print(result)

    assert result == {
        0: bytes.fromhex(
            "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
        )
    }


@automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_singlesig_sh_wpkh_1to2(cmd: BitcoinCommand):

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "sh(wpkh(@0))",
        [
            "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = cmd.sign_psbt(psbt, wallet, None)

    assert result == {
        0: bytes.fromhex(
            "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
        )
    }


@automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_1to2(cmd: BitcoinCommand):

    # PSBT for a legacy 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    result = cmd.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    assert result == {
        0: bytes.fromhex(
            "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"
        )
    }


@automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_2to2(cmd: BitcoinCommand):
    # PSBT for a legacy 2-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    result = cmd.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == {
        0: bytes.fromhex(
            "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
        ),
        1: bytes.fromhex(
            "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
        ),
    }


# def test_sign_psbt_legacy(cmd: BitcoinCommand):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUhIh4AAAA="

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = cmd.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_legacy_p2pkh(cmd: BitcoinCommand):
#     # test from app-bitcoin

#     # legacy address
#     # PSBT for a legacy 1-input, 1-output + 1-change address spend
#     unsigned_raw_psbt_base64 = 'cHNidP8BAHcBAAAAAVf4kTUeYOlEcY8d8StPd7ZCzGMUYYS+3Gx7xkoMCzneAAAAAAAAAAAAAqCGAQAAAAAAGXapFHrmeHmDxejS4X7xcPdZBWw2A6fYiKygfAEAAAAAABl2qRQYm4Or/V0O+Y+/NZTJXMU7RJdK6oisAAAAAAABAOICAAAAAV33ueIMUtHaJwGiRKSXVCFSZvAW9r139kClIAzR+340AQAAAGtIMEUCIQDIBpV0KZNcXWH1SCI8NTbcc5/jUYFLzp7cFpTlpcJavwIgE+MHsLSIWstkzP+vX0eU8gUEAyXrw2wlh4fEiLA4wrsBIQOLpGLX3WWRfs5FQUKQO7NioLQS0YQdUgh62IFka2zcz/3///8CFAwDAAAAAAAZdqkUs+F8Te+KORSO1vrX3G/r4w3TJMuIrDBXBQAAAAAAGXapFOCok4BjXxi37glUbZYyMry5kkEriKz+BB0AAQMEAQAAAAAAAA=='

#     # expected sig: 3044022012f6a643d1d1a558912e0935dbd6a9694fe87c841e0f699c7cbb7c818503c115022064585f9b69c3452183a74ee7f00ae0452139e2c73b156dfd6ac835bea4fdf975

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = cmd.sign_psbt(psbt)

#     print(result)


@automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_multisig_wsh(cmd: BitcoinCommand):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
    )

    wallet_hmac = bytes.fromhex(
        "df87ec380ff3b9c8bd5bcc3d233cf7b8155f95beb25c668de448c8418c4ee383"
    )

    psbt = open_psbt_from_file(f"{tests_root}/psbt/multisig/wsh-2of2.psbt")

    result = cmd.sign_psbt(psbt, wallet, wallet_hmac)

    assert result == {
        0: bytes.fromhex(
            "304402206ab297c83ab66e573723892061d827c5ac0150e2044fed7ed34742fedbcfb26e0220319cdf4eaddff63fc308cdf53e225ea034024ef96de03fd0939b6deeea1e8bd301"
        )
    }

    print(result)


# def test_sign_psbt_legacy_wrong_non_witness_utxo(cmd: BitcoinCommand):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     # The spend is valid, but the non-witness utxo is wrong; therefore, it should fail the hash test
#     # TODO: this fails PSBT decoding; need to make a version we can control for this test.

#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUySC0BAAA="
#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     with pytest.raises(IncorrectDataError):
#         cmd.sign_psbt(psbt)
