# The tests in this file are for the MuSig2 standalone python signer implementation in test_utils.

from bitcoin_client.ledger_bitcoin.key import ExtendedKey
from bitcoin_client.ledger_bitcoin import WalletPolicy
from bitcoin_client.ledger_bitcoin.psbt import PSBT

from test_utils.musig2 import HotMusig2Cosigner, run_musig2_test


def test_musig2_hotsigner_keypath():
    cosigner_1_xpriv = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz"
    cosigner_1_xpub = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"

    wallet_policy = WalletPolicy(
        name="Musig for my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[cosigner_1_xpub, cosigner_2_xpub]
    )

    psbt_b64 = "cHNidP8BAIACAAAAAWbcwfJ78yV/+Jn0waX9pBWhDp2pZCm0GuTEXe2wXcP2AQAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIPSL0RqGcuiQxWUrpyqc9CJwAk7i1Wk1p+YZWmGpB5tmIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxg0AAAAAAAAAAAADAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "f3f6d4ae955af42665667ccff4edc9244d9143ada53ba26aee036258e0ffeda9")
    ]

    signer_1 = HotMusig2Cosigner(wallet_policy, cosigner_1_xpriv)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)


def test_musig2_hotsigner_scriptpath():
    cosigner_1_xpriv = "tprv8gFWbQBTLFhbVcpeAJ1nGbPetqLo2a5Duqu3E5wXUFJ4auLcBAfwhJscGbPjzKNvpCdG3KK3BLCTLi8YKy4PXnA1hxdowdpTaMqTcF5ZpUz"
    cosigner_1_xpub = ExtendedKey.deserialize(
        cosigner_1_xpriv).neutered().to_string()

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = ExtendedKey.deserialize(
        cosigner_2_xpriv).neutered().to_string()

    wallet_policy = WalletPolicy(
        name="Musig2 in the scriptpath",
        descriptor_template="tr(@0/**,pk(musig(@1,@2)/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            cosigner_1_xpub,
            cosigner_2_xpub
        ]
    )

    psbt_b64 = "cHNidP8BAFoCAAAAAeyfHxrwzXffQqF9egw6KMS7RwCLP4rW95dxtXUKYJGFAQAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDZqQIMWvfc0h2w2z6+0vTt0z1YoUHA6JHynopzSe3hgiIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyDGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7BxqzAIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxi0BkW61VIaT9Qaz/k0SzoZ1UBsjkrXzPqXQbCbBjbNZP/kAAAAAAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYIJFutVSGk/UGs/5NEs6GdVAbI5K18z6l0GwmwY2zWT/5AAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "ba6d1d859dbc471999fff1fc5b8740fdacadd64a10c8d62de76e39a1c8dcd835")
    ]

    signer_1 = HotMusig2Cosigner(wallet_policy, cosigner_1_xpriv)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)
