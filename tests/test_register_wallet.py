from ledger_bitcoin import AddressType, MultisigWallet, WalletPolicy
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.exception import DenyError
from ragger.navigator import Navigator, NavInsID
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient

from .instructions import register_wallet_instruction_approve, register_wallet_instruction_approve_long, register_wallet_instruction_approve_unusual, register_wallet_instruction_reject, Instructions
import hmac
from hashlib import sha256

import pytest


def run_register_test(navigator: Navigator, client: RaggerClient, speculos_globals, wallet_policy:
                      WalletPolicy, instructions: Instructions,
                      test_name: str = "") -> None:
    wallet_policy_id, wallet_hmac = client.register_wallet(wallet_policy, navigator,
                                                           instructions=instructions,
                                                           testname=test_name)

    assert wallet_policy_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_policy_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_wallet_accept_legacy(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals, MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            "[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW",
            "[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_accept_sh_wit(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals, MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g",
            "[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_accept_wit(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals, MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_with_long_name(navigator: Navigator, firmware: Firmware, client:
                                        RaggerClient, test_name: str, speculos_globals):
    name = "Cold storage with a pretty long name that requires 64 characters"
    assert len(name) == 64

    run_register_test(navigator, client, speculos_globals, MultisigWallet(
        name=name,
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_reject_header(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    if not firmware.name.startswith("nano"):
        pytest.skip()

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet, navigator,
                               instructions=register_wallet_instruction_reject(
                                   firmware),
                               testname=test_name)

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_register_wallet_invalid_pubkey_version(navigator: Navigator, firmware: Firmware, client:
                                                RaggerClient, test_name: str):
    # This is the same wallet policy as the test_register_wallet_accept_wit test,
    # but the external pubkey has the wrong BIP32 version (mainnet xpub instead of testnet tpub).
    # An older version of the app ignored the version for external pubkeys, while now it rejects it
    # if the version is wrong, as a sanity check.
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(MultisigWallet(
            name="Cold storage",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                "[76223a6e/48'/1'/0'/2']xpub6DjjtjxALtJSP9dKRKuhejeTpZc711gUGZyS9nCM5GAtrNTDuMBZD2FcndJoHst6LYNbJktm4NmJyKqspLi5uRmtnDMAdcPAf2jiSj9gFTX",
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        ), navigator, instructions=register_wallet_instruction_approve(firmware), testname=test_name)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0


def test_register_wallet_invalid_names(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str):
    too_long_name = "This wallet name is much too long since it requires 65 characters"
    assert len(too_long_name) == 65

    for invalid_name in [
        "",  # empty name not allowed
        too_long_name,  # 65 characters is too long
        " Test", "Test ",  # can't start with spaces
        "Tæst",  # characters out of allowed range
    ]:
        wallet = MultisigWallet(
            name=invalid_name,
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
        )

        with pytest.raises(ExceptionRAPDU) as e:
            client.register_wallet(wallet, None,
                                   testname=test_name)

        assert DeviceException.exc.get(e.value.status) == IncorrectDataError
        # defined in error_codes.h
        EC_REGISTER_WALLET_UNACCEPTABLE_POLICY_NAME = 0x0000

        if invalid_name == too_long_name:
            # We don't return an error code for name too long
            assert len(e.value.data) == 0
        else:
            assert len(e.value.data) == 2
            error_code = int.from_bytes(e.value.data, 'big')
            assert error_code == EC_REGISTER_WALLET_UNACCEPTABLE_POLICY_NAME


def test_register_wallet_missing_key(client: RaggerClient):
    wallet = WalletPolicy(
        name="Missing a key",
        descriptor_template="wsh(multi(2,@0/**,@1/**))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            # the second key is missing
        ],
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError
    assert len(e.value.data) == 0


def test_register_wallet_unsupported_policy(navigator: Navigator, firmware: Firmware, client:
                                            RaggerClient, test_name: str):
    # valid policies, but not supported (might change in the future)

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Unsupported",
            descriptor_template="pk(@0/**)",  # bare pubkey, not supported
            keys_info=[
                "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            ]
        ),
            navigator,
            testname=test_name)

    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0


def test_register_miniscript_long_policy(navigator: Navigator, firmware: Firmware, client:
                                         RaggerClient, test_name: str, speculos_globals):
    # This test makes sure that policies longer than 256 bytes work as expected on all devices
    wallet = WalletPolicy(
        name="Long policy",
        descriptor_template=f"wsh(and_v(and_v(v:pk(@0/**),or_c(pk(@1/**),or_c(pk(@2/**),v:older(1000)))),and_v(v:hash256(0563fb3e85cbc61b134941ad6610a2b0dfd77543dfb77a5433ff3cb538213807),and_v(v:hash256(ad3391a00bad00a6a03f907b3fcc2f369a88be038c63c7db7f43b01e097efbbe),hash256(137dfa9b54a538200c94e3c9dd1a59b431e3b89aef8093fc910df48a98cb06d9)))))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
        ])

    wallet_id, wallet_hmac = client.register_wallet(wallet, navigator,
                                                    instructions=register_wallet_instruction_approve_long(
                                                        firmware),
                                                    testname=test_name)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_wallet_not_sane_policy(navigator: Navigator, firmware: Firmware, client:
                                         RaggerClient, test_name: str):
    # pubkeys in the keys vector must be all different
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Unsupported policy",
            descriptor_template=f"wsh(c:andor(pk(@0/<0;1>/*),pk_k(@1/**),and_v(v:pk(@2/<2;3>/*),pk_k(@3/**))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                # the next key is again the internal pubkey, but without key origin information
                "tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]),
            navigator,
            testname=test_name
        )

    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2

    # defined in error_codes.h
    EC_REGISTER_WALLET_POLICY_NOT_SANE = 0x0001

    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    # Key placeholders referring to the same key must have distinct derivations
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Unsupported policy",
            descriptor_template="wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@0/**),sln:older(12960)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]),
            navigator,
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Unsupported policy",
            # even a partial overlap (derivation @0/1 being used twice) is not acceptable
            descriptor_template="wsh(thresh(3,pk(@0/**),s:pk(@1/**),s:pk(@0/<1;2>/*),sln:older(12960)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]),
            navigator,
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    # Miniscript policy with timelock mixing
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Timelock mixing is bad",
            descriptor_template="wsh(thresh(2,c:pk_k(@0/**),ac:pk_k(@1/**),altv:after(1000000000),altv:after(100)))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]),
            navigator,
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    # Miniscript policy that does not always require a signature
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="No need for sig",
            descriptor_template="wsh(or_d(multi(1,@0/**),or_b(multi(3,@1/**,@2/**,@3/**),su:after(500000))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
                "tpubDF6JT5K4izwALMpFv7fQrpWr5bGUMEoWphkzTVJH8jTfgirNEgGZnxsWJDCCxhg2UnW5RcD9Tx8aVAdoM734X5bnRGmJUujz26uQ5gAC1nE",
                "tpubDF4kujkh5dAhC1pFgBToZybXdvJFXXGX4BWdDxWqP7EUpG8gxkfMQeDjGPDnTr9e4NrkFmDM1ocav3Jz6x79CRZbxGr9dzFokJLuvDDnyRh",
            ]),
            navigator,
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    # Malleable policy, even if it requires a signature
    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Malleable",
            descriptor_template="wsh(c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(@0/**),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(@1/**))))",
            keys_info=[
                "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
                "tpubDDV6FDLcCieWUeN7R3vZK2Qs3KuQed3ScTY9EiwMXvyCkLjDbCb8RXaAgWDbkG4tW1BMKVF1zERHnyt78QKd4ZaAYGMJMpvHPwgSSU1AxZ3",
            ]),
            navigator,
            testname=test_name
        )
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE

    # TODO: we can probably not trigger stack and ops limits with the current limits we have on the
    # miniscript policy size; otherwise it would be worth to add tests for them, too.


def test_register_unusual_singlesig_accounts(navigator: Navigator, firmware: Firmware, client:
                                             RaggerClient, test_name: str, speculos_globals):
    # Tests that it is possible to register policies for single-signature using unusual paths

    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Unusual Legacy",
        descriptor_template="pkh(@0/**)",
        keys_info=["[f5acc2fd/1'/2'/3']tpubDCsHVWwqALkDzorr5zdc91Wj93zR3so1kUEH6LWsPrLtC9MVPjb8NEQwCzhPM4TEFP6KbgmTb7xAsyrbf3oEBh31Q7iAKhzMHj2FZ5YGNrr"]
    ),
        instructions=register_wallet_instruction_approve_unusual(firmware),
        test_name=f"{test_name}_Unusual_Legacy")

    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Unusual Nested SegWit",
        descriptor_template="sh(wpkh(@0/**))",
        keys_info=["[f5acc2fd/1'/2'/3']tpubDCsHVWwqALkDzorr5zdc91Wj93zR3so1kUEH6LWsPrLtC9MVPjb8NEQwCzhPM4TEFP6KbgmTb7xAsyrbf3oEBh31Q7iAKhzMHj2FZ5YGNrr"]
    ),
        instructions=register_wallet_instruction_approve_unusual(firmware),
        test_name=f"{test_name}_Unusual_Nested_Segwit")

    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Unusual Native SegWit",
        descriptor_template="wpkh(@0/**)",
        keys_info=["[f5acc2fd/1'/2'/3']tpubDCsHVWwqALkDzorr5zdc91Wj93zR3so1kUEH6LWsPrLtC9MVPjb8NEQwCzhPM4TEFP6KbgmTb7xAsyrbf3oEBh31Q7iAKhzMHj2FZ5YGNrr"]
    ),
        instructions=register_wallet_instruction_approve_unusual(firmware),
        test_name=f"{test_name}_Unusual_Native_Segwit")

    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Unusual Taproot",
        descriptor_template="tr(@0/**)",
        keys_info=["[f5acc2fd/1'/2'/3']tpubDCsHVWwqALkDzorr5zdc91Wj93zR3so1kUEH6LWsPrLtC9MVPjb8NEQwCzhPM4TEFP6KbgmTb7xAsyrbf3oEBh31Q7iAKhzMHj2FZ5YGNrr"]
    ),
        instructions=register_wallet_instruction_approve_unusual(firmware),
        test_name=f"{test_name}_Unusual_Taproot")


def test_register_wallet_tr_script_pk(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Taproot foreign internal key, and our script key",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_tr_with_nums_keypath(navigator: Navigator, firmware: Firmware, client:
                                              RaggerClient, test_name: str, speculos_globals):
    # The taproot keypath is unspendable; the UX must explicitly mark it as a 'dummy' key.
    # The tpub for @0 is obtained by using the NUMS (Nothing-Up-My-Sleeve) key defined in BIP-0341,
    # and using 32 zero bytes as the chaincode.
    # It is important that the app can detect and clearly communicate to the user that the key is
    # a dummy one, therefore unusable for spending.
    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Taproot unspendable keypath",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    ),
        instructions=register_wallet_instruction_approve(firmware),
        test_name=test_name)


def test_register_wallet_tr_script_sortedmulti(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str, speculos_globals):
    run_register_test(navigator, client, speculos_globals, WalletPolicy(
        name="Taproot single-key or multisig 2-of-2",
        descriptor_template="tr(@0/**,sortedmulti_a(2,@1/**,@2/**))",
        keys_info=[
            "[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY",
            "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
            "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
        ],
    ),
        instructions=register_wallet_instruction_approve_long(firmware),
        test_name=test_name)
