import pytest

from bitcoin_client.command import BitcoinCommand

from bitcoin_client.psbt import PSBT
from bitcoin_client.wallet import PolicyMapWallet


def test_sign_psbt_singlesig_sh_wpkh_1to2(cmd: BitcoinCommand):

    # legacy address
    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    filename = "./psbt/singlesig/sh-wpkh-1to2.psbt"
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)

    wallet = PolicyMapWallet(
        "", "sh(wpkh(@0))", ["[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**"])

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = cmd.sign_psbt(psbt, wallet)

    print(result)


def test_sign_psbt_singlesig_wpkh_1to2(cmd: BitcoinCommand):

    # legacy address
    # PSBT for a legacy 1-input 2-output spend (1 change address)
    filename = "./psbt/singlesig/wpkh-1to2.psbt"
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)

    wallet = PolicyMapWallet(
        "", "wpkh(@0)", ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"])

    result = cmd.sign_psbt(psbt, wallet)

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    print(result)


def test_sign_psbt_singlesig_wpkh_2to2(cmd: BitcoinCommand):

    # legacy address
    # PSBT for a legacy 2-input 2-output spend (1 change address)
    filename = "./psbt/singlesig/wpkh-2to2.psbt"
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)

    wallet = PolicyMapWallet(
        "", "wpkh(@0)", ["[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"])

    result = cmd.sign_psbt(psbt, wallet)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    print(result)


# def test_sign_psbt_legacy(cmd):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUhIh4AAAA="

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = cmd.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_legacy_p2pkh(cmd):
#     # test from app-bitcoin

#     # legacy address
#     # PSBT for a legacy 1-input, 1-output + 1-change address spend
#     unsigned_raw_psbt_base64 = 'cHNidP8BAHcBAAAAAVf4kTUeYOlEcY8d8StPd7ZCzGMUYYS+3Gx7xkoMCzneAAAAAAAAAAAAAqCGAQAAAAAAGXapFHrmeHmDxejS4X7xcPdZBWw2A6fYiKygfAEAAAAAABl2qRQYm4Or/V0O+Y+/NZTJXMU7RJdK6oisAAAAAAABAOICAAAAAV33ueIMUtHaJwGiRKSXVCFSZvAW9r139kClIAzR+340AQAAAGtIMEUCIQDIBpV0KZNcXWH1SCI8NTbcc5/jUYFLzp7cFpTlpcJavwIgE+MHsLSIWstkzP+vX0eU8gUEAyXrw2wlh4fEiLA4wrsBIQOLpGLX3WWRfs5FQUKQO7NioLQS0YQdUgh62IFka2zcz/3///8CFAwDAAAAAAAZdqkUs+F8Te+KORSO1vrX3G/r4w3TJMuIrDBXBQAAAAAAGXapFOCok4BjXxi37glUbZYyMry5kkEriKz+BB0AAQMEAQAAAAAAAA=='

#     # expected sig: 3044022012f6a643d1d1a558912e0935dbd6a9694fe87c841e0f699c7cbb7c818503c115022064585f9b69c3452183a74ee7f00ae0452139e2c73b156dfd6ac835bea4fdf975

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = cmd.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_multisig(cmd):
#     # legacy address

#     unsigned_raw_psbt_base64 = "cHNidP8BAH0CAAAAAQ5HHvTpLBrLUe/IZg+NP2mTbqnJsr/3L/m8gcUe/PRkAQAAAAD9////ArmoOwAAAAAAFgAUNcbg3W08hLFrqIXcpzrIY9C1k+xwEQEAAAAAACIAIP3uRBxW5bBtDfgsEkxwcBSlyhlli+C5hWvKFvHtMln3AAAAAAABAIgCAAAAAZXf7wah/zeZl5w2fzI91OWHTXbYoKMhQy721zey6JUvAAAAABcWABSPsnHXGKDY3oyXy+y9qkU7T0ui6/7///8CEPdqqQEAAAAWABRO796NdCbgG+W8qJf2alrndA2/ZsO6PAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JrEGB4AAQEfw7o8AAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmiIGAny3XTSwBcTrn2K78sRX12OOgT51fvzsj6aGd9lQtjZiGPWswv1UAACAAQAAgAAAAIAAAAAAAAAAAAAiAgJxtbd5rYcIOFh3l7z28MeuxavnanCdck9I0uJs+HTwoBj1rML9VAAAgAEAAIAAAACAAQAAAAAAAAAAAA=="
#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = cmd.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_legacy_wrong_non_witness_utxo(cmd):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     # The spend is valid, but the non-witness utxo is wrong; therefore, it should fail the hash test
#     # TODO: this fails PSBT decoding; need to make a version we can control for this test.

#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUySC0BAAA="
#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     with pytest.raises(IncorrectDataError):
#         cmd.sign_psbt(psbt)
