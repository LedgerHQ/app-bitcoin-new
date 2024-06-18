
from pathlib import Path

import pytest

from ledger_bitcoin import WalletPolicy, Client
from ledger_bitcoin.psbt import PSBT

from test_utils import txmaker

tests_root: Path = Path(__file__).parent


def make_psbt(wallet_policy: WalletPolicy, n_inputs: int, n_outputs: int) -> PSBT:
    in_amounts = [10000 + 10000 * i for i in range(n_inputs)]
    total_in = sum(in_amounts)
    out_amounts = [total_in // n_outputs - i for i in range(n_outputs)]

    change_index = 1

    psbt = txmaker.createPsbt(
        wallet_policy,
        in_amounts,
        out_amounts,
        [i == change_index for i in range(n_outputs)]
    )

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    return psbt


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_singlesig_pkh(client: Client, n_inputs: int, benchmark):
    # PSBT for a legacy 2-output spend (1 change address)

    wallet = WalletPolicy(
        "",
        "pkh(@0/**)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
        ],
    )

    psbt = make_psbt(wallet, n_inputs, 2)

    def sign_tx():
        result = client.sign_psbt(psbt, wallet, None)

        assert len(result) == n_inputs

    benchmark.pedantic(sign_tx, rounds=1)


@pytest.mark.parametrize("n_inputs", [1, 3, 10])
def test_perf_sign_psbt_singlesig_wpkh(client: Client, n_inputs: int, benchmark):
    # PSBT for a segwit 2-output spend (1 change address)

    wallet = WalletPolicy(
        "",
        "wpkh(@0/**)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P"
        ],
    )

    psbt = make_psbt(wallet, n_inputs, 2)

    def sign_tx():
        result = client.sign_psbt(psbt, wallet, None)

        assert len(result) == n_inputs

    benchmark.pedantic(sign_tx, rounds=1)
