import pytest

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.exception.errors import DenyError

from test_utils import automation


@automation("automations/sign_message_accept.json")
def test_sign_message(client: Client):
    msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks."
    path = "m/44'/1'/0'/0/0"
    result = client.sign_message(msg, path)

    assert result == "IOR4YRVlmJGMx+H7PgQvHzWAF0HAgrUggQeRdnoWKpypfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="


@automation("automations/sign_message_accept.json")
def test_sign_message_accept(client: Client):
    message = "Hello world!"

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/0"
    )

    assert res == 'IEOK4+JMK7FToR7XMzFCoAYh1nud1IKm9Wq3vXLSVk/lBay8rHCRp9bP6riyR5NDqXYyYf7cXgMQTHNz3SemwZI='


@automation("automations/sign_message_accept.json")
def test_sign_message_accept_long(client: Client):
    # Test with a long message that is split in multiple leaves in the Merkle tree

    message = "The root problem with conventional currency is all the trust that's required to make it work. The central bank must be trusted not to debase the currency, but the history of fiat currencies is full of breaches of that trust. Banks must be trusted to hold our money and transfer it electronically, but they lend it out in waves of credit bubbles with barely a fraction in reserve. We have to trust them with our privacy, trust them not to let identity thieves drain our accounts. Their massive overhead costs make micropayments impossible."

    res = client.sign_message(
        message,
        "m/84'/1'/0'/0/8"
    )

    assert res == 'H4frM6TYm5ty1MAf9o/Zz9Qiy3VEldAYFY91SJ/5nYMAZY1UUB97fiRjKW8mJit2+V4OCa1YCqjDqyFnD9Fw75k='


@automation("automations/sign_message_reject.json")
def test_sign_message_reject(client: Client):
    with pytest.raises(DenyError):
        client.sign_message("Anything", "m/44'/1'/0'/0/0")
