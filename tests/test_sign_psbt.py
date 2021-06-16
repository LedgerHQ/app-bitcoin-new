import pytest

from bitcoin_client.command import BitcoinCommand

from bitcoin_client.common import AddressType
from bitcoin_client.psbt import PSBT
from bitcoin_client.exception import IncorrectDataError


def test_sign_psbt_singlesig_wpkh_1to2(cmd: BitcoinCommand):

    # legacy address
    # PSBT for a legacy 1-input 1-output spend
    filename = "./psbt/singlesig/wpkh-1to2.psbt"
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)

    result = cmd.sign_psbt(psbt)

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
