
from hashlib import sha256
from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.exception import DenyError
from bitcoin_client.wallet import MultisigWallet
from bitcoin_client.common import AddressType

from utils import automation
from typing import List

import pytest


@automation("automations/register_wallet_accept.json")
def test_register_and_get_address(cmd, speculos_globals):
    # test for a native segwit wallet (bech32 address)

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**"
        ]
    )

    wallet_id, wallet_sig = cmd.register_wallet(wallet)

    assert wallet_id == wallet.id

    pk: VerifyingKey = VerifyingKey.from_string(
        speculos_globals.master_compressed_pubkey,
        curve=SECP256k1,
        hashfunc=sha256
    )

    assert pk.verify(signature=wallet_sig,
                     data=wallet.serialize(),
                     hashfunc=sha256,
                     sigdecode=sigdecode_der) is True


    res = cmd.get_wallet_address(wallet, wallet_sig, 3)

    assert res == "tb1qwuxulrpu5d02eag4tphxhamaa24s8sk8d5s7kw340cesr0wf87csks3c9a"
