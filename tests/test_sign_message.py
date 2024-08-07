import pytest

from ledger_bitcoin.exception.errors import DenyError
from ledger_bitcoin.exception.device_exception import DeviceException
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU
from ragger_bitcoin import RaggerClient
from .instructions import message_instruction_approve, message_instruction_approve_long, message_instruction_reject


def test_sign_message(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks."
    path = "m/44'/1'/0'/0/0"
    result = client.sign_message(msg, path, navigator,
                                 instructions=message_instruction_approve(firmware),
                                 testname=test_name)

    assert result == "IOR4YRVlmJGMx+H7PgQvHzWAF0HAgrUggQeRdnoWKpypfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="


def test_sign_message_64bytes(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Version 2.2.2 introduced a bug where signing a 64 bytes message would fail; this test is to avoid regressions
    msg = "a" * 64
    path = "m/44'/1'/0'/0/0"
    client.sign_message(msg, path, navigator,
                        instructions=message_instruction_approve(firmware, save_screenshot=False),
                        testname=test_name)


def test_sign_message_accept(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    message = "Hello world!"

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/0",
        navigator,
        instructions=message_instruction_approve(firmware),
        testname=test_name
    )

    assert res == 'IEOK4+JMK7FToR7XMzFCoAYh1nud1IKm9Wq3vXLSVk/lBay8rHCRp9bP6riyR5NDqXYyYf7cXgMQTHNz3SemwZI='


def test_sign_message_accept_long(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Test with a long message that is split in multiple leaves in the Merkle tree
    message = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible."

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8",
        navigator,
        instructions=message_instruction_approve_long(firmware),
        testname=test_name
    )

    assert res == 'H4frM6TYm5ty1MAf9o/Zz9Qiy3VEldAYFY91SJ/5nYMAZY1UUB97fiRjKW8mJit2+V4OCa1YCqjDqyFnD9Fw75k='


def test_sign_message_reject(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_message("Anything", "m/44'/1'/0'/0/0",
                            navigator,
                            instructions=message_instruction_reject(firmware),
                            testname=test_name
                            )

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0


def test_sign_message_accept_non_ascii(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Test with a message that contains non ascii char
    message = "Hello\nworld!"

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8",
        navigator,
        instructions=message_instruction_approve(firmware),
        testname=test_name
    )

    assert res == 'IGGk2UM12aQGtigJ7XCLJEXQl3bdKgx0G3CIt0ADSWknfAHqs+9+9OPZSjGrjyp46GjztGzUAnCa/DDMrSIAfbg='


def test_sign_message_accept_too_long(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    # Test with a message that is too long to be displayed
    message = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible. The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible. The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible."

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8",
        navigator,
        instructions=message_instruction_approve(firmware),
        testname=test_name
    )

    assert res == 'IDAl9RThAyunmYuol9DaDs/CScUpiol3FDSjIjyK9y0tc/x1HWrbT/ufdkPFY1Bmi+L9hc3ip1me2RmufprVuNk='


def test_sign_message_hash_reject(navigator: Navigator, firmware: Firmware, client: RaggerClient, test_name: str):
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_message("Hello\nworld!",
                            "m/44'/1'/0'/0/0",
                            navigator,
                            instructions=message_instruction_reject(firmware),
                            testname=test_name
                            )

    assert DeviceException.exc.get(e.value.status) == DenyError
    assert len(e.value.data) == 0
