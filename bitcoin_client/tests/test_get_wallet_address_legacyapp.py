from bitcoin_client.ledger_bitcoin import Client, WalletPolicy


def test_get_wallet_address_singlesig_legacy(client: Client):
    # legacy address (P2PKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="pkh(@0/**)",
        keys_info=[
            f"[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT",
        ],
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "mz5vLWdM1wHVGSmXUkhKVvZbJ2g4epMXSm"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "myFCUBRCKFjV7292HnZtiHqMzzHrApobpT"


def test_get_wallet_address_singlesig_wit(client: Client):
    # bech32 address (P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="wpkh(@0/**)",
        keys_info=[
            f"[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P",
        ],
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "tb1qzdr7s2sr0dwmkwx033r4nujzk86u0cy6fmzfjk"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "tb1qlrvzyx8jcjfj2xuy69du9trtxnsvjuped7e289"


def test_get_wallet_address_singlesig_sh_wit(client: Client):
    # wrapped segwit addresses (P2SH-P2WPKH)
    wallet = WalletPolicy(
        name="",
        descriptor_template="sh(wpkh(@0/**))",
        keys_info=[
            f"[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3",
        ],
    )
    assert client.get_wallet_address(wallet, None, 0,  0, False) == "2MyHkbusvLomaarGYMqyq7q9pSBYJRwWcsw"
    assert client.get_wallet_address(wallet, None, 1, 15, False) == "2NAbM4FSeBQG4o85kbXw2YNfKypcnEZS9MR"
