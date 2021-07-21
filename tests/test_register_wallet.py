from bitcoin_client.command import BitcoinCommand
from bitcoin_client.common import AddressType
from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet

from .utils import automation

from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

import pytest


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_legacy(cmd: BitcoinCommand, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/0']tpubDE7NQymr4AFtZwx94XxPNFpTduLxQB4JhTFC52AC213kND6dahQ6eznZeWcsZ5wEgZ2cVrZqdEWDB6Tvt82BYEmaia8pgFJGAj9ijtSfbxD/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**"
        ]
    )

    wallet_id, sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_sh_wit(cmd: BitcoinCommand, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**"
        ]
    )

    wallet_id, sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_wit(cmd: BitcoinCommand, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**"
        ]
    )

    wallet_id, sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


@automation("automations/register_wallet_reject.json")
def test_register_wallet_reject_header(cmd):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/0']tpubDE7NQymr4AFtZwx94XxPNFpTduLxQB4JhTFC52AC213kND6dahQ6eznZeWcsZ5wEgZ2cVrZqdEWDB6Tvt82BYEmaia8pgFJGAj9ijtSfbxD/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**"
        ]
    )

    with pytest.raises(DenyError):
        cmd.register_wallet(wallet)


# TODO: add more tests for:
#  - rejections at different stages
#  - responses to different types of wrong data from the host
