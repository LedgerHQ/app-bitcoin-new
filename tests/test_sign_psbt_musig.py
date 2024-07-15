
from pathlib import Path

from hashlib import sha256
import hmac


from ledger_bitcoin.client_base import Client, MusigPartialSignature, MusigPubNonce
from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PSBT
from ragger.navigator import Navigator
from ragger.firmware import Firmware

from ledger_bitcoin.wallet import WalletPolicy
from ragger_bitcoin import RaggerClient
from test_utils import SpeculosGlobals, bip0327
from test_utils.musig2 import HotMusig2Cosigner, Musig2KeyPlaceholder, PsbtMusig2Cosigner, TrDescriptorTemplate, run_musig2_test
from .instructions import *

tests_root: Path = Path(__file__).parent


# for now, we assume that there's a single internal musig placeholder, with a single
class LedgerMusig2Cosigner(PsbtMusig2Cosigner):
    """
    Implements a PsbtMusig2Cosigner that uses a BitcoinClient
    """

    def __init__(self, client: Client, wallet_policy: WalletPolicy, wallet_hmac: bytes) -> None:
        super().__init__()

        self.client = client
        self.wallet_policy = wallet_policy
        self.wallet_hmac = wallet_hmac

        self.fingerprint = client.get_master_fingerprint()

        desc_tmpl = TrDescriptorTemplate.from_string(
            wallet_policy.descriptor_template)

        self.pubkey = None
        for _, (placeholder, _) in enumerate(desc_tmpl.placeholders()):
            if not isinstance(placeholder, Musig2KeyPlaceholder):
                continue

            for i in placeholder.key_indexes:
                key_info = self.wallet_policy.keys_info[i]
                if key_info[0] == "[" and key_info[1:9] == self.fingerprint.hex():
                    xpub = key_info[key_info.find(']') + 1:]
                    self.pubkey = ExtendedKey.deserialize(xpub)
                    break

            if self.pubkey is not None:
                break

        if self.pubkey is None:
            raise ValueError("no musig with an internal key in wallet policy")

    def get_participant_pubkey(self) -> bip0327.Point:
        return bip0327.cpoint(self.pubkey.pubkey)

    def generate_public_nonces(self, psbt: PSBT) -> None:
        print("PSBT before nonce generation:", psbt.serialize())
        res = self.client.sign_psbt(psbt, self.wallet_policy, self.wallet_hmac)
        print("Pubnonces:", res)
        for (input_index, yielded) in res:
            if isinstance(yielded, MusigPubNonce):
                psbt_key = (
                    yielded.participant_pubkey,
                    yielded.aggregate_pubkey,
                    yielded.tapleaf_hash
                )
                print("Adding pubnonce to psbt for Ledger input", input_index)
                print("Key:", psbt_key)
                print("Value:", yielded.pubnonce)

                assert len(yielded.aggregate_pubkey) == 33

                psbt.inputs[input_index].musig2_pub_nonces[psbt_key] = yielded.pubnonce

    def generate_partial_signatures(self, psbt: PSBT) -> None:
        print("PSBT before partial signature generation:", psbt.serialize())
        res = self.client.sign_psbt(psbt, self.wallet_policy, self.wallet_hmac)
        print("Ledger result of second round:", res)
        for (input_index, yielded) in res:
            if isinstance(yielded, MusigPartialSignature):
                psbt_key = (
                    yielded.participant_pubkey,
                    yielded.aggregate_pubkey,
                    yielded.tapleaf_hash
                )

                print("Adding partial signature to psbt for Ledger input", input_index)
                print("Key:", psbt_key)
                print("Value:", yielded.partial_signature)

                psbt.inputs[input_index].musig2_partial_sigs[psbt_key] = yielded.partial_signature
            elif isinstance(yielded, MusigPubNonce):
                raise ValueError("Expected partial signatures, got a pubnonce")


def test_sign_psbt_musig2_keypath(client: RaggerClient, speculos_globals: SpeculosGlobals):
    cosigner_1_xpub = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

    cosigner_2_xpriv = "tprv8gFWbQBTLFhbX3EK3cS7LmenwE3JjXbD9kN9yXfq7LcBm81RSf8vPGPqGPjZSeX41LX9ZN14St3z8YxW48aq5Yhr9pQZVAyuBthfi6quTCf"
    cosigner_2_xpub = "tpubDCwYjpDhUdPGQWG6wG6hkBJuWFZEtrn7j3xwG3i8XcQabcGC53xWZm1hSXrUPFS5UvZ3QhdPSjXWNfWmFGTioARHuG5J7XguEjgg7p8PxAm"

    wallet_policy = WalletPolicy(
        name="Musig for my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[cosigner_1_xpub, cosigner_2_xpub]
    )
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    psbt_b64 = "cHNidP8BAIACAAAAAWbcwfJ78yV/+Jn0waX9pBWhDp2pZCm0GuTEXe2wXcP2AQAAAAD9////AQAAAAAAAAAARGpCVGhpcyBpbnB1dHMgaGFzIHR3byBwdWJrZXlzIGJ1dCB5b3Ugb25seSBzZWUgb25lLiAjbXBjZ2FuZyByZXZlbmdlAAAAAAABASuf/gQAAAAAACJRIPSL0RqGcuiQxWUrpyqc9CJwAk7i1Wk1p+YZWmGpB5tmIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxg0AAAAAAAAAAAADAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "f3f6d4ae955af42665667ccff4edc9244d9143ada53ba26aee036258e0ffeda9")
    ]

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)


def test_sign_psbt_musig2_scriptpath(client: RaggerClient, speculos_globals: SpeculosGlobals):
    cosigner_1_xpub = "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"

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
    wallet_hmac = hmac.new(
        speculos_globals.wallet_registration_key, wallet_policy.id, sha256).digest()

    psbt_b64 = "cHNidP8BAFoCAAAAAeyfHxrwzXffQqF9egw6KMS7RwCLP4rW95dxtXUKYJGFAQAAAAD9////AQAAAAAAAAAAHmocTXVzaWcyLiBOb3cgZXZlbiBpbiBTY3JpcHRzLgAAAAAAAQErOTAAAAAAAAAiUSDZqQIMWvfc0h2w2z6+0vTt0z1YoUHA6JHynopzSe3hgiIVwethFsEeXf/x51pIczoAIsj9RoVePIBTyk/rOMW8B6uIIyDGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7BxqzAIRbGANErPozSP7sjGM7KD11/WcKOe0InwGoEZz9MPQ7Bxi0BkW61VIaT9Qaz/k0SzoZ1UBsjkrXzPqXQbCbBjbNZP/kAAAAAAAAAAAMAAAABFyDrYRbBHl3/8edaSHM6ACLI/UaFXjyAU8pP6zjFvAeriAEYIJFutVSGk/UGs/5NEs6GdVAbI5K18z6l0GwmwY2zWT/5AAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    sighashes = [
        bytes.fromhex(
            "ba6d1d859dbc471999fff1fc5b8740fdacadd64a10c8d62de76e39a1c8dcd835")
    ]

    signer_1 = LedgerMusig2Cosigner(client, wallet_policy, wallet_hmac)
    signer_2 = HotMusig2Cosigner(wallet_policy, cosigner_2_xpriv)

    run_musig2_test(wallet_policy, psbt, [signer_1, signer_2], sighashes)
