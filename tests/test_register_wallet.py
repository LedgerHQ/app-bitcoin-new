from bitcoin_client.ledger_bitcoin import Client, AddressType, MultisigWallet, PolicyMapWallet
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from bitcoin_client.ledger_bitcoin.exception import DenyError

from test_utils import has_automation

import hmac
from hashlib import sha256

import pytest


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_legacy(client: Client, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_sh_wit(client: Client, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_accept_wit(client: Client, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_with_long_name(client: Client, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage with a pretty long name that requires 64 characters",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )


@has_automation("automations/register_wallet_reject.json")
def test_register_wallet_reject_header(client: Client):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    with pytest.raises(DenyError):
        client.register_wallet(wallet)


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_invalid_names(client: Client):
    for invalid_name in [
        "",  # empty name not allowed
        "Very long walletz",  # 17 characters is too long
        " Test", "Test ",  # can't start with spaces
        "Tæst",  # characters out of allowed range
    ]:
        wallet = MultisigWallet(
            name=invalid_name,
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        )

    with pytest.raises(IncorrectDataError):
        client.register_wallet(wallet)


@has_automation("automations/register_wallet_accept.json")
def test_register_wallet_unsupported_policy(client: Client):
    # valid policies, but not supported (might change in the future)

    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Unsupported",
            policy_map="pk(@0/**)",  # bare pubkey, not supported
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            ]
        ))


def test_register_wallet_not_sane_policy(client: Client):
    # pubkeys in the keys vector must be all different
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Unsupported policy",
            policy_map=f"wsh(c:andor(pk(@0/<0;1>/*),pk_k(@1/**),and_v(v:pk(@2/<2;3>/*),pk_k(@3/**))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                # the next key is again the internal pubkey, but without key origin information
                "tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]))

    # Key placeholders referring to the same key must have distinct derivations
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Unsupported policy",
            policy_map="wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@0/**),sln:older(12960)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]))
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Unsupported policy",
            # even a partial overlap (derivation @0/1 being used twice) is not acceptable
            policy_map="wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@0/<1;2>/*),sln:older(12960)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]))

    # Miniscript policy with timelock mixing
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Timelock mixing is bad",
            policy_map="wsh(thresh(2,c:pk_k(@0/**),ac:pk_k(@1/**),altv:after(1000000000),altv:after(100)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]))

    # Miniscript policy that does not always require a signature
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="No need for sig",
            policy_map="wsh(or_d(multi(1,@0/**),or_b(multi(3,@1/**,@2/**,@3/**),su:after(500000))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
                "tpubDF6JT5K4izwALMpFv7fQrpWr5bGUMEoWphkzTVJH8jTfgirNEgGZnxsWJDCCxhg2UnW5RcD9Tx8aVAdoM734X5bnRGmJUujz26uQ5gAC1nE",
                "tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh",
            ]))

    # Malleable policy, even if it requires a signature
    with pytest.raises(NotSupportedError):
        client.register_wallet(PolicyMapWallet(
            name="Malleable",
            policy_map="wsh(c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(@1/**))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]))

    # TODO: we can probably not trigger stack and ops limits with the current limits we have on the
    # miniscript policy size; otherwise it would be worth to add tests for them, too.
