from bitcoin_client.common import AddressType

# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

# TODO: add tests with display=True and non-standard path

def test_get_address(cmd):
    # legacy address
    addr = cmd.get_address(
        address_type=AddressType.LEGACY,
        bip32_path="m/44'/0'/0'/0/0",
        display=False
    )
    assert addr == "1KKLP5MNa9mmWnEziT5skyu7PZ8A4eFisB"

    # bech32 address
    addr = cmd.get_address(
        address_type=AddressType.WIT,
        bip32_path="m/84'/0'/0'/0/0",
        display=False
    )

    assert addr == "bc1qqtl9jlrwcr3fsfcjj2du7pu6fcgaxl5dsw2vyg"

    # P2SH-P2WPKH address
    addr = cmd.get_address(
        address_type=AddressType.SH_WIT,
        bip32_path="m/49'/0'/0'/0/0",
        display=False
    )

    assert addr == "31mceY4tx8cr75vQLLFcK1Gp2VkGdyZfZy"
