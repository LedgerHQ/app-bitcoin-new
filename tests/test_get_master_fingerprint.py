from bitcoin_client.command import BitcoinCommand
from conftest import SpeculosGlobals


def test_get_master_fingerprint(cmd: BitcoinCommand, speculos_globals: SpeculosGlobals):
    assert cmd.get_master_fingerprint() == speculos_globals.master_key_fingerprint.to_bytes(4, byteorder="big")
