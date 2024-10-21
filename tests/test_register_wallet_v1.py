# Tests using the V1 version of the wallet policy language, used before version 2.1.0 of the app
# Make sure we remain compatible for some time.

from ledger_bitcoin import AddressType, MultisigWallet, WalletPolicy, WalletType
from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError, DenyError
from ledger_bitcoin.exception.device_exception import DeviceException

from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavInsID
from ragger.firmware import Firmware
from ragger_bitcoin import RaggerClient

from .instructions import register_wallet_instruction_approve, register_wallet_instruction_approve_long, register_wallet_instruction_approve_unusual, register_wallet_instruction_reject

import hmac
from hashlib import sha256

import pytest


def test_register_wallet_accept_legacy_v1(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.LEGACY,
        threshold=2,
        keys_info=[
            f"[5c9e228d/48'/1'/0'/0']tpubDEGquuorgFNb8bjh5kNZQMPtABJzoWwNm78FUmeoPkfRtoPF7JLrtoZeT3J3ybq1HmC3Rn1Q8wFQ8J5usanzups5rj7PJoQLNyvq8QbJruW/**",
            f"[f5acc2fd/48'/1'/0'/0']tpubDFAqEGNyad35WQAZMmPD4vgBXnjH16RGciLdWekPe4f4d5JzoHVu1PS86Sy4Tm63vDf8rfV3UjifhrRuSUDfiZj5KPffTPyZ4ZXBKvjD8jm/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet, navigator,
                                                    instructions=register_wallet_instruction_approve(
                                                        firmware),
                                                    testname=test_name)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_wallet_accept_sh_wit_v1(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.SH_WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/1']tpubDE7NQymr4AFtcJXi9TaWZtrhAdy8QyKmT4U6b9qYByAxCzoyMJ8zw5d8xVLVpbTRAEqP8pVUxjLE2vDt1rSFjaiS8DSz1QcNZ8D1qxUMx1g/**",
            f"[f5acc2fd/48'/1'/0'/1']tpubDFAqEGNyad35YgH8zxvxFZqNUoPtr5mDojs7wzbXQBHTZ4xHeVXG6w2HvsKvjBpaRpTmjYDjdPg5w2c6Wvu8QBkyMDrmBWdCyqkDM7reSsY/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet, navigator,
                                                    instructions=register_wallet_instruction_approve(
                                                        firmware),
                                                    testname=test_name)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_wallet_accept_wit_v1(navigator: Navigator, firmware: Firmware, client:
                                       RaggerClient, test_name: str, speculos_globals):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    wallet_id, wallet_hmac = client.register_wallet(wallet, navigator,
                                                    instructions=register_wallet_instruction_approve(
                                                        firmware),
                                                    testname=test_name)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )


def test_register_wallet_reject_header_v1(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str):
    if not firmware.name.startswith("nano"):
        pytest.skip()

    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet, navigator,
                               instructions=register_wallet_instruction_reject(
                                   firmware),
                               testname=test_name)

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_register_wallet_invalid_names_v1(navigator: Navigator, firmware: Firmware, client:
                                          RaggerClient, test_name: str):
    too_long_name = "This wallet name is much too long since it requires 65 characters"
    assert len(too_long_name) == 65

    for invalid_name in [
        "",  # empty name not allowed
        too_long_name,
        # " Test", "Test ",  # can't start or end with spaces
        # "Tæst",  # characters out of allowed range
    ]:
        print("Testing with:", invalid_name)  # TODO: remove
        wallet = MultisigWallet(
            name=invalid_name,
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
            ],
            version=WalletType.WALLET_POLICY_V1
        )

        with pytest.raises(ExceptionRAPDU) as e:
            client.register_wallet(wallet, None)

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


def test_register_wallet_unsupported_policy_v1(navigator: Navigator, firmware: Firmware, client:
                                               RaggerClient, test_name: str):
    # valid policies, but not supported (might change in the future)

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(WalletPolicy(
            name="Unsupported",
            descriptor_template="pk(@0)",  # bare pubkey, not supported
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            ],
            version=WalletType.WALLET_POLICY_V1
        ),
            navigator,
            testname=test_name)

    # NotSupportedError
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    assert len(e.value.data) == 0

    with pytest.raises(ExceptionRAPDU) as e:
        # Not supporting keys without wildcard
        client.register_wallet(MultisigWallet(
            name="Cold storage",
            address_type=AddressType.WIT,
            threshold=2,
            keys_info=[
                f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
                f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
            ],
            version=WalletType.WALLET_POLICY_V1
        ),
            navigator,
            testname=test_name)

    # NotSupportedError
    assert DeviceException.exc.get(e.value.status) == NotSupportedError
    # defined in error_codes.h
    EC_REGISTER_WALLET_POLICY_NOT_SANE = 0x0001

    assert len(e.value.data) == 2
    error_code = int.from_bytes(e.value.data, 'big')
    assert error_code == EC_REGISTER_WALLET_POLICY_NOT_SANE
