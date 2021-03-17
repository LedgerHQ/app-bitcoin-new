# default speculos seed: glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin

# TODO: add tests with display=True and non-standard path

def test_get_pubkey(cmd):
    pub_key = cmd.get_pubkey(
        bip32_path="m",  # root pubkey
        display=False
    )

    assert pub_key == "xpub661MyMwAqRbcGtJ6aNMHg7WyD3FoeAUoeoQ2SnqsqjgPaeL8KML8nDLH2c6cFk1EhVDzaFSCDgtLSua2dW7k7Z8hYvbXDRgHmr32jBV1S12"


    pub_key = cmd.get_pubkey(
        bip32_path="m/44'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "xpub6HEjXpLNm1tB1WP5jmhNPynqe11usBFJbFpVQkDZGoyQ6MQ9vg4q8AYEhkxJzwyUYsBviW9c47xc4N5niV8vu9PHqaqqkMKM7us3VDY8qCy"

    # BIP32 derivation for P2SH-P2WPKH address
    pub_key = cmd.get_pubkey(
        bip32_path="m/49'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "xpub6GQw8JZk9kq3ty5xQNN87XA5DEuAk4twW4ALaB4nGmax9n1MRuWhMWdstptYTfZTWUFpUstsRMA1NbGFC6Uve6bLV1tnBbBD8sSng27bBpW"

    # bech32 address
    pub_key = cmd.get_pubkey(
        bip32_path="m/84'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "xpub6FoRKpF5QPnC4JVtJiFhaeTALpY91SvGDCZHG6rw1LWatoMDWkBhdb9MkTZawGcqpyy8YvjYmXWc8pPNgXBnoHttY6xeSAfPUhhwmo2uRzV"