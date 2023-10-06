# Tests using the V1 version of the wallet policy language, used before version 2.1.0 of the app
# Make sure we remain compatible for some time.

import pytest

import threading

from decimal import Decimal

from typing import List

from pathlib import Path

from bitcoin_client.ledger_bitcoin import Client, WalletPolicy, MultisigWallet, AddressType, WalletType, PartialSignature
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError

from bitcoin_client.ledger_bitcoin.psbt import PSBT
from bitcoin_client.ledger_bitcoin.wallet import AddressType
from speculos.client import SpeculosClient

from test_utils import has_automation, bip0340, txmaker

from embit.script import Script
from embit.networks import NETWORKS

from test_utils.speculos import automation

tests_root: Path = Path(__file__).parent


CURRENCY_TICKER = "TEST"


def format_amount(ticker: str, amount: int) -> str:
    """Formats an amounts in sats as shown in the app: divided by 10_000_000, with no trailing zeroes."""
    assert amount >= 0
    btc_amount = f"{(amount/100_000_000):.8f}".rstrip('0').rstrip('.')
    return f"{ticker} {btc_amount}"


def should_go_right(event: dict):
    """Returns true if the current text event implies a "right" button press to proceed."""

    if event["text"].startswith("Review"):
        return True
    elif event["text"].startswith("Amount"):
        return True
    elif event["text"].startswith("Address"):
        return True
    elif event["text"].startswith("Confirm"):
        return True
    elif event["text"].startswith("Fees"):
        return True
    return False


def ux_thread_sign_psbt(speculos_client: SpeculosClient, all_events: List[dict]):
    """Completes the signing flow always going right and accepting at the appropriate time, while collecting all the events in all_events."""

    # press right until the last screen (will press the "right" button more times than needed)

    while True:
        event = speculos_client.get_next_event()
        all_events.append(event)

        if should_go_right(event):
            speculos_client.press_and_release("right")
        elif event["text"] == "Approve":
            speculos_client.press_and_release("both")
        elif event["text"] == "Accept":
            speculos_client.press_and_release("both")
            break


def ux_thread_sign_psbt_stax(speculos_client: SpeculosClient, all_events: List[dict]):
    """Completes the signing flow always going right and accepting at the appropriate time, while collecting all the events in all_events."""

    first_approve = True
    while True:
        event = speculos_client.get_next_event()
        all_events.append(event)

        if event["text"] == "Tap to continue":
            speculos_client.finger_touch(55, 550)

        elif first_approve and ("Approve" in event["text"] or "Hold" in event["text"]):
            first_approve = False
            speculos_client.finger_touch(55, 550, 3)

        elif event["text"] == "TRANSACTION":
            break

        elif "CONFIRMED" in event["text"]:
            first_approve = True


def parse_signing_events(events: List[dict]) -> dict:
    ret = dict()

    cur_output_index = -1

    ret["addresses"] = []
    ret["amounts"] = []
    ret["fees"] = ""
    next_step = ""
    keywords = ("Amount", "Address", "Fees", "Accept", "Approve")

    for ev in events:
        if ev["text"].startswith("output #"):
            idx_str = ev["text"][8:]

            assert int(idx_str) - 1 == cur_output_index + 1  # should not skip outputs

            cur_output_index = int(idx_str) - 1

            ret["addresses"].append("")
            ret["amounts"].append("")
            next_step = ""

        elif ev["text"].startswith("Tap"):
            ret["addresses"].append("")
            ret["amounts"].append("")
            next_step = ""
            continue

        elif ev["text"].startswith(keywords):
            next_step = ev["text"]
            continue

        if next_step.startswith("Address"):
            if len(ret["addresses"]) == 0:
                ret["addresses"].append("")

            ret["addresses"][-1] += ev["text"].strip()

        elif next_step.startswith("Fees"):
            ret["fees"] += ev["text"]

        elif next_step.startswith("Amount"):
            if len(ret["amounts"]) == 0:
                ret["amounts"].append("")
            ret["amounts"][-1] += ev["text"].strip()

    return ret


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_pkh_1to1_v1(client: Client):

    # PSBT for a legacy 1-input 1-output spend (no change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = WalletPolicy(
        "",
        "pkh(@0)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
    #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
    result = client.sign_psbt(psbt, wallet, None)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718"),
            signature=bytes.fromhex(
                "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
            )
        )
    )]


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_sh_wpkh_1to2_v1(client: Client):

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "sh(wpkh(@0))",
        [
            "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = client.sign_psbt(psbt, wallet, None)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67"),
            signature=bytes.fromhex(
                "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
            )
        )
    )]


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_1to2_v1(client: Client):

    # PSBT for a legacy 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    result = client.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068"),
            signature=bytes.fromhex(
                "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"
            )
        )
    )]


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_2to2_v1(client: Client):
    # PSBT for a legacy 2-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    result = client.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3"),
            signature=bytes.fromhex(
                "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
            )
        )
    ), (
        1,
        PartialSignature(
            pubkey=bytes.fromhex("0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0"),
            signature=bytes.fromhex(
                "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
            )
        )
    )]


@has_automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_multisig_wsh_v1(client: Client):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    wallet_hmac = bytes.fromhex(
        "d6434852fb3caa7edbd1165084968f1691444b3cfc10cf1e431acbbc7f48451f"
    )

    psbt = open_psbt_from_file(f"{tests_root}/psbt/multisig/wsh-2of2.psbt")

    result = client.sign_psbt(psbt, wallet, wallet_hmac)

    assert result == [(
        0,
        PartialSignature(
            pubkey=bytes.fromhex("036b16e8c1f979fa4cc0f05b6a300affff941459b6f20de77de55b0160ef8e4cac"),
            signature=bytes.fromhex(
                "304402206ab297c83ab66e573723892061d827c5ac0150e2044fed7ed34742fedbcfb26e0220319cdf4eaddff63fc308cdf53e225ea034024ef96de03fd0939b6deeea1e8bd301"
            )
        )
    )]


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_taproot_1to2_v1(client: Client):
    # PSBT for a p2tr 1-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/tr-1to2-sighash-all.psbt")

    wallet = WalletPolicy(
        "",
        "tr(@0)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    result = client.sign_psbt(psbt, wallet, None)
    assert len(result) == 1

    # Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
    # Therefore, for this testcase we hard-code the sighash (which was validated with Bitcoin Core 22.0 when the
    # transaction was sent), and we verify the produced Schnorr signature with the reference bip340 implementation.

    # sighash verified with bitcoin-core
    sighash0 = bytes.fromhex("7A999E5AD6F53EA6448E7026061D3B4523F957999C430A5A492DFACE74AE31B6")

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0_psbt = psbt.inputs[0].witness_utxo.scriptPubKey[2:]

    idx0, partial_sig0 = result[0]
    assert idx0 == 0
    assert partial_sig0.pubkey == pubkey0_psbt

    # the sighash 0x01 is appended to the signature
    assert len(partial_sig0.signature) == 64+1
    assert partial_sig0.signature[-1] == 0x01

    assert bip0340.schnorr_verify(sighash0, pubkey0_psbt, partial_sig0.signature[:-1])


def test_sign_psbt_singlesig_wpkh_4to3_v1(client: Client, comm: SpeculosClient, is_speculos: bool,
                                          model: str):
    # PSBT for a segwit 4-input 3-output spend (1 change address)
    # this test also checks that addresses, amounts and fees shown on screen are correct

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    n_ins = 4
    n_outs = 3

    in_amounts = [10000 + 10000 * i for i in range(n_ins)]
    sum_in = sum(in_amounts)
    out_amounts = [sum_in // n_outs - i for i in range(n_outs)]

    change_index = 1

    psbt = txmaker.createPsbt(
        wallet,
        in_amounts,
        out_amounts,
        [i == change_index for i in range(n_outs)]
    )

    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    fees_amount = sum_in - sum_out

    all_events: List[dict] = []

    if model == "stax":
        x = threading.Thread(target=ux_thread_sign_psbt_stax, args=[comm, all_events])
    else:
        x = threading.Thread(target=ux_thread_sign_psbt, args=[comm, all_events])

    x.start()
    result = client.sign_psbt(psbt, wallet, None)
    x.join()

    assert len(result) == n_ins

    parsed_events = parse_signing_events(all_events)

    assert parsed_events["fees"] == format_amount(CURRENCY_TICKER, fees_amount)

    shown_out_idx = 0
    for out_idx in range(n_outs):
        if out_idx != change_index:
            out_amt = psbt.tx.vout[out_idx].nValue
            assert parsed_events["amounts"][shown_out_idx] == format_amount(CURRENCY_TICKER, out_amt)

            out_addr = Script(psbt.tx.vout[out_idx].scriptPubKey).address(network=NETWORKS["test"])
            assert parsed_events["addresses"][shown_out_idx] == out_addr

            shown_out_idx += 1


def test_sign_psbt_singlesig_large_amount_v1(client: Client, comm: SpeculosClient, is_speculos:
                                             bool, model: str):
    # Test with a transaction with an extremely large amount

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    in_amounts = [21_000_000*100_000_000]
    out_amounts = [21_000_000*100_000_000 - 100_000]

    psbt = txmaker.createPsbt(wallet, in_amounts, out_amounts, [False])

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    fees_amount = sum_in - sum_out

    all_events: List[dict] = []

    if model == "stax":
        x = threading.Thread(target=ux_thread_sign_psbt_stax, args=[comm, all_events])
    else:
        x = threading.Thread(target=ux_thread_sign_psbt, args=[comm, all_events])

    x.start()
    result = client.sign_psbt(psbt, wallet, None)
    x.join()

    assert len(result) == 1

    parsed_events = parse_signing_events(all_events)

    assert parsed_events["fees"] == format_amount(CURRENCY_TICKER, fees_amount)

    out_amt = psbt.tx.vout[0].nValue
    assert parsed_events["amounts"][0] == format_amount(CURRENCY_TICKER, out_amt)


@pytest.mark.timeout(0)  # disable timeout
@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_512to256_v1(client: Client, enable_slow_tests: bool):
    # PSBT for a transaction with 512 inputs and 256 outputs (maximum currently supported in the app)
    # Very slow test (esp. with DEBUG enabled), so disabled unless the --enableslowtests option is used

    if not enable_slow_tests:
        pytest.skip()

    n_inputs = 512
    n_outputs = 256

    wallet = WalletPolicy(
        "",
        "tr(@0)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    psbt = txmaker.createPsbt(
        wallet,
        [10000 + 10000 * i for i in range(n_inputs)],
        [999 + 99 * i for i in range(n_outputs)],
        [i == 42 for i in range(n_outputs)]
    )

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == n_inputs


def ux_thread_accept_prompt_stax(speculos_client: SpeculosClient, all_events: List[dict]):
    """Completes the signing flow always going right and accepting at the appropriate time, while collecting all the events in all_events."""

    while True:
        event = speculos_client.get_next_event()
        all_events.append(event)
        if "Tap to continue" in event["text"]:
            speculos_client.finger_touch(55, 550)
            break


def test_sign_psbt_fail_11_changes_v1(client: Client, comm: SpeculosClient, is_speculos: bool,
                                      model: str):
    # PSBT for transaction with 11 change addresses; the limit is 10, so it must fail with NotSupportedError
    # before any user interaction

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    psbt = txmaker.createPsbt(
        wallet,
        [11 * 100_000_000 + 1234],
        [100_000_000] * 11,
        [True] * 11,
    )

    all_events: List[dict] = []

    if model == "stax":
        x = threading.Thread(target=ux_thread_accept_prompt_stax, args=[comm, all_events])

        x.start()
    with pytest.raises(NotSupportedError):
        client.sign_psbt(psbt, wallet, None)


def test_sign_psbt_fail_wrong_non_witness_utxo_v1(client: Client, is_speculos: bool):
    # PSBT for transaction with the wrong non-witness utxo for an input.
    # It must fail with IncorrectDataError before any user interaction.

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    psbt = txmaker.createPsbt(
        wallet,
        [3 * 100_000_000],
        [1 * 100_000_000, 2 * 100_000_000],
        [False, True]
    )

    # Modify the non_witness_utxo so that the txid does not matches
    wit = psbt.inputs[0].non_witness_utxo
    wit.nLockTime = wit.nLockTime ^ 1  # change one bit of nLockTime arbitrarily to change the txid
    wit.rehash()
    psbt.inputs[0].non_witness_utxo = wit

    client._no_clone_psbt = True
    with pytest.raises(IncorrectDataError):
        client.sign_psbt(psbt, wallet, None)
    client._no_clone_psbt = False


def test_sign_psbt_with_opreturn_v1(client: Client, comm: SpeculosClient):
    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    psbt_b64 = "cHNidP8BAKMCAAAAAZ0gZDu3l28lrZWbtsuoIfI07zpsaXXMe6sMHHJn03LPAAAAAAD+////AgAAAAAAAAAASGpGVGhlIFRpbWVzIDAzL0phbi8yMDA5IENoYW5jZWxsb3Igb24gYnJpbmsgb2Ygc2Vjb25kIGJhaWxvdXQgZm9yIGJhbmtzLsGVmAAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ8AAAAAAAEAcQIAAAABnpp88I3RXEU5b28rI3GGAXaWkk+w1sEqWDXFXdacKg8AAAAAAP7///8CgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmvNabSkBAAAAFgAUCA6eZPSQK9gnq8ngOSaQ0ZdPeIVBAAAAAQEfgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmiIGAny3XTSwBcTrn2K78sRX12OOgT51fvzsj6aGd9lQtjZiGPWswv1UAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAA=="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    with automation(comm, "automations/sign_with_default_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet, None)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_segwit_v16_v1(client: Client, comm: SpeculosClient):
    # This psbt contains an output with future psbt version 16 (corresponding to address
    # tb1sqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4hu3px).
    # The app should accept it nonetheless.

    psbt_b64 = "cHNidP8BAH0CAAAAAZvg4s1Yxz9DddwBeI+qqU7hcldqGSgWPXuZZReEFYvKAAAAAAD+////AqdTiQAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ9AQg8AAAAAACJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAHECAAAAAYWOSCXXmA0ztidPI5A6FskW99o7nWNVeFP7rXND5B9aAAAAAAD+////AoCWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JrzWm0pAQAAABYAFF7XSHCIZoptcIrXIWce1tKqp11EaQAAAAEBH4CWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JoiBgJ8t100sAXE659iu/LEV9djjoE+dX787I+mhnfZULY2Yhj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallet = WalletPolicy(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
        version=WalletType.WALLET_POLICY_V1
    )

    with automation(comm, "automations/sign_with_default_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet, None)

    assert len(hww_sigs) == 1
