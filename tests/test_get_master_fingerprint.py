from bitcoin_client.ledger_bitcoin import Client
from .conftest import SpeculosGlobals


def test_get_master_fingerprint(client: Client, speculos_globals: SpeculosGlobals):
    assert client.get_master_fingerprint() == speculos_globals.master_key_fingerprint
