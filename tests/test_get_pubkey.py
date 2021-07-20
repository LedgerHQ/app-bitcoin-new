from bitcoin_client.command import BitcoinCommand

# TODO: add tests with display=True and non-standard path


def test_get_pubkey(cmd: BitcoinCommand):
    pub_key = cmd.get_pubkey(
        bip32_path="m",  # root pubkey
        display=False
    )

    assert pub_key == "tpubD6NzVbkrYhZ4YgUx2ZLNt2rLYAMTdYysCRzKoLu2BeSHKvzqPaBDvf17GeBPnExUVPkuBpx4kniP964e2MxyzzazcXLptxLXModSVCVEV1T"

    pub_key = cmd.get_pubkey(
        bip32_path="m/44'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "tpubDHcN44A4UHqdHJZwBxgTbu8Cy87ZrZkN8tQnmJGhcijHqe4rztuvGcD4wo36XSviLmiqL5fUbDnekYaQ7LzAnaqauBb9RsyahsTTFHdeJGd"

    # BIP32 derivation for P2SH-P2WPKH address
    pub_key = cmd.get_pubkey(
        bip32_path="m/49'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "tpubDGnZeYPRs2nWAmGorZMDKSVSYMzpjTQ13gkdvj7vcgLqu4g4W8MnVxJi8ryKzAWhJNnj6TQjxSz44mkraxLAXY3dYce5s7qSiq3CRxqyAE4"

    # bech32 address
    pub_key = cmd.get_pubkey(
        bip32_path="m/84'/1'/0'/0/0",
        display=False
    )

    assert pub_key == "tpubDGB3r44m7fjeL6gjkuEnnZnXfwdnzqRKkq9acev5MFGUe61vay2nn2pBzVeNTma5ctW3AWFRJdLepzsz5P32gjMBbhhx7hKd4fJMXsacZ6L"
