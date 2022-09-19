from pathlib import Path

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.client_legacy import LegacyClient


tests_root: Path = Path(__file__).parent


def test_client_legacy(client: Client):
    # tests that the library correctly instatiates the LegacyClient and not the new one,
    # since the version of the app binary being tested is an old one
    assert isinstance(client, LegacyClient)
