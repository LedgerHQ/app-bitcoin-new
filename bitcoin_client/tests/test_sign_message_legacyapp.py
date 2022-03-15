from bitcoin_client.ledger_bitcoin import Client

from test_utils import has_automation


@has_automation("automations/sign_message.json")
def test_sign_message(client: Client):
    msg = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks."
    path = "m/44'/1'/0'/0/0"
    result = client.sign_message(msg, path)

    assert result == "IOR4YRVlmJGMx+H7PgQvHzWAF0HAgrUggQeRdnoWKpypfaAberpvF+XbOCM5Cd/ljogNyU3w2OIL8eYCyZ6Ru2k="
