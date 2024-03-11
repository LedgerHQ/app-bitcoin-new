from ragger_bitcoin import RaggerClient
from .conftest import SpeculosGlobals


def test_get_master_fingerprint(client: RaggerClient, speculos_globals: SpeculosGlobals):
    assert client.get_master_fingerprint() == speculos_globals.master_key_fingerprint
