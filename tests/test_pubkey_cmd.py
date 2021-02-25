def test_get_public_key(cmd):
    pub_key, chain_code = cmd.get_public_key(
        bip32_path="m/44'/0'/0'/0/0",
        display=False
    )  # type: bytes, bytes

    assert len(pub_key) == 65
    assert len(chain_code) == 32

    pub_key2, chain_code2 = cmd.get_public_key(
        bip32_path="m/44'/1'/0'/0/0",
        display=False
    )  # type: bytes, bytes

    assert len(pub_key2) == 65
    assert len(chain_code2) == 32
