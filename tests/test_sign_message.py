import pytest

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.exception.errors import DenyError

from test_utils import has_automation


@has_automation("automations/sign_message_accept.json")
def test_sign_message(client: Client):
    msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks."
    path = "m/44'/1'/0'/0/0"
    result = client.sign_message(msg, path)

    assert result == "IOR4YRVlmJGMx+H7PgQvHzWAF0HAgrUggQeRdnoWKpypfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="


@has_automation("automations/sign_message_accept.json")
def test_sign_message_accept(client: Client):
    message = "Hello world!"

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/0"
    )

    assert res == 'IEOK4+JMK7FToR7XMzFCoAYh1nud1IKm9Wq3vXLSVk/lBay8rHCRp9bP6riyR5NDqXYyYf7cXgMQTHNz3SemwZI='


@has_automation("automations/sign_message_accept.json")
def test_sign_message_accept_long(client: Client):
    # Test with a long message that is split in multiple leaves in the Merkle tree

    message = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible."

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8"
    )

    assert res == 'H4frM6TYm5ty1MAf9o/Zz9Qiy3VEldAYFY91SJ/5nYMAZY1UUB97fiRjKW8mJit2+V4OCa1YCqjDqyFnD9Fw75k='


@has_automation("automations/sign_message_reject.json")
def test_sign_message_reject(client: Client):
    with pytest.raises(DenyError):
        client.sign_message("Anything", "m/44'/1'/0'/0/0")


@has_automation("automations/sign_message_accept.json")
def test_sign_message_accept_non_ascii(client: Client):
    # Test with a message that contains non ascii char

    message = "Hello\nworld!"

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8"
    )

    assert res == 'IGGk2UM12aQGtigJ7XCLJEXQl3bdKgx0G3CIt0ADSWknfAHqs+9+9OPZSjGrjyp46GjztGzUAnCa/DDMrSIAfbg='


@has_automation("automations/sign_message_accept.json")
def test_sign_message_accept_too_long(client: Client):
    # Test with a message that is too long to be displayed

    message = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible. The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible. The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible."

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8"
    )

    assert res == 'IDAl9RThAyunmYuol9DaDs/CScUpiol3FDSjIjyK9y0tc/x1HWrbT/ufdkPFY1Bmi+L9hc3ip1me2RmufprVuNk='


@has_automation("automations/sign_message_reject.json")
def test_sign_message_hash_reject(client: Client):
    with pytest.raises(DenyError):
        client.sign_message("Hello\nworld!", "m/44'/1'/0'/0/0")


