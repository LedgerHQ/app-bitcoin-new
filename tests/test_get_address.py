from bitcoin_client.command import BitcoinCommand
from bitcoin_client.common import AddressType

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

# TODO: add tests with display=True and non-standard path


def test_get_address_legacy(cmd: BitcoinCommand):
    # legacy address
    addr = cmd.get_address(
        address_type=AddressType.LEGACY, bip32_path="m/44'/1'/0'/0/0", display=False
    )
    assert addr == "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm"


def test_get_address_wit(cmd: BitcoinCommand):
    # bech32 address
    addr = cmd.get_address(
        address_type=AddressType.WIT, bip32_path="m/84'/1'/0'/0/0", display=False
    )

    assert addr == "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk"


def test_get_address_sh_wit(cmd: BitcoinCommand):
    # P2SH-P2WPKH address
    addr = cmd.get_address(
        address_type=AddressType.SH_WIT, bip32_path="m/49'/1'/0'/0/0", display=False
    )

    assert addr == "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw"
