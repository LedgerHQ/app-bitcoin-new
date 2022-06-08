import pytest

import threading

from decimal import Decimal

from typing import List

from pathlib import Path

from bitcoin_client.ledger_bitcoin import Client, PolicyMapWallet, MultisigWallet, AddressType
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
# For nano X/S+ OCR used in speculos misreads 'S'. See caveats.txt
CURRENCY_TICKER_ALT = "TET"


def format_amount(ticker: str, amount: int) -> str:
    """Formats an amounts in sats as shown in the app: divided by 10_000_000, with no trailing zeroes."""
    assert amount >= 0

    return f"{ticker} {str(Decimal(amount) / 100_000_000)}"


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

        elif ev["text"].startswith(keywords):
            next_step = ev["text"]
            continue

        if next_step.startswith("Address"):
            ret["addresses"][-1] += ev["text"]

        elif next_step.startswith("Fees"):
            ret["fees"] += ev["text"]

        elif next_step.startswith("Amount"):
            ret["amounts"][-1] += ev["text"]

    return ret


def open_psbt_from_file(filename: str) -> PSBT:
    raw_psbt_base64 = open(filename, "r").read()

    psbt = PSBT()
    psbt.deserialize(raw_psbt_base64)
    return psbt


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_pkh_1to1(client: Client):

    # PSBT for a legacy 1-input 1-output spend (no change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/pkh-1to1.psbt")

    wallet = PolicyMapWallet(
        "",
        "pkh(@0)",
        [
            "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "02ee8608207e21028426f69e76447d7e3d5e077049f5e683c3136c2314762a4718",
    #  "signature" : "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
    result = client.sign_psbt(psbt, wallet, None)

    assert result == {
        0: bytes.fromhex(
            "3045022100e55b3ca788721aae8def2eadff710e524ffe8c9dec1764fdaa89584f9726e196022012a30fbcf9e1a24df31a1010356b794ab8de438b4250684757ed5772402540f401"
        )
    }


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_sh_wpkh_1to2(client: Client):

    # PSBT for a wrapped segwit 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/sh-wpkh-1to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "sh(wpkh(@0))",
        [
            "[f5acc2fd/49'/1'/0']tpubDC871vGLAiKPcwAw22EjhKVLk5L98UGXBEcGR8gpcigLQVDDfgcYW24QBEyTHTSFEjgJgbaHU8CdRi9vmG4cPm1kPLmZhJEP17FMBdNheh3/**"
        ],
    )

    # expected sigs:
    # #0:
    #  "pubkey" : "024ba3b77d933de9fa3f9583348c40f3caaf2effad5b6e244ece8abbfcc7244f67",
    #  "signature" : "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
    result = client.sign_psbt(psbt, wallet, None)

    assert result == {
        0: bytes.fromhex(
            "30440220720722b08489c2a50d10edea8e21880086c8e8f22889a16815e306daeea4665b02203fcf453fa490b76cf4f929714065fc90a519b7b97ab18914f9451b5a4b45241201"
        )
    }


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_1to2(client: Client):

    # PSBT for a legacy 1-input 2-output spend (1 change address)
    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-1to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03ee2c3d98eb1f93c0a1aa8e5a4009b70eb7b44ead15f1666f136b012ad58d3068",
    #   "signature" : "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"

    assert result == {
        0: bytes.fromhex(
            "3045022100ab44f34dd7e87c9054591297a101e8500a0641d1d591878d0d23cf8096fa79e802205d12d1062d925e27b57bdcf994ecf332ad0a8e67b8fe407bab2101255da632aa01"
        )
    }


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_2to2(client: Client):
    # PSBT for a legacy 2-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == {
        0: bytes.fromhex(
            "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
        ),
        1: bytes.fromhex(
            "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
        ),
    }


@has_automation("automations/sign_with_default_wallet_missing_nonwitnessutxo_accept.json")
def test_sign_psbt_singlesig_wpkh_2to2_missing_nonwitnessutxo(client: Client):
    # Same as the previous test, but the non-witness-utxo is missing.
    # The app should sign after a warning.

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/wpkh-2to2.psbt")

    # remove the non-witness-utxo field
    for input in psbt.inputs:
        input.non_witness_utxo = None

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None)

    # expected sigs
    # #0:
    #   "pubkey" : "03455ee7cedc97b0ba435b80066fc92c963a34c600317981d135330c4ee43ac7a3",
    #   "signature" : "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
    # #1:
    #   "pubkey" : "0271b5b779ad870838587797bcf6f0c7aec5abe76a709d724f48d2e26cf874f0a0",
    #   "signature" : "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"

    assert result == {
        0: bytes.fromhex(
            "304402206b3e877655f08c6e7b1b74d6d893a82cdf799f68a5ae7cecae63a71b0339e5ce022019b94aa3fb6635956e109f3d89c996b1bfbbaf3c619134b5a302badfaf52180e01"
        ),
        1: bytes.fromhex(
            "3045022100e2e98e4f8c70274f10145c89a5d86e216d0376bdf9f42f829e4315ea67d79d210220743589fd4f55e540540a976a5af58acd610fa5e188a5096dfe7d36baf3afb94001"
        ),
    }


# def test_sign_psbt_legacy(client: Client):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUhIh4AAAA="

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = client.sign_psbt(psbt)

#     print(result)


# def test_sign_psbt_legacy_p2pkh(client: Client):
#     # test from app-bitcoin

#     # legacy address
#     # PSBT for a legacy 1-input, 1-output + 1-change address spend
#     unsigned_raw_psbt_base64 = 'cHNidP8BAHcBAAAAAVf4kTUeYOlEcY8d8StPd7ZCzGMUYYS+3Gx7xkoMCzneAAAAAAAAAAAAAqCGAQAAAAAAGXapFHrmeHmDxejS4X7xcPdZBWw2A6fYiKygfAEAAAAAABl2qRQYm4Or/V0O+Y+/NZTJXMU7RJdK6oisAAAAAAABAOICAAAAAV33ueIMUtHaJwGiRKSXVCFSZvAW9r139kClIAzR+340AQAAAGtIMEUCIQDIBpV0KZNcXWH1SCI8NTbcc5/jUYFLzp7cFpTlpcJavwIgE+MHsLSIWstkzP+vX0eU8gUEAyXrw2wlh4fEiLA4wrsBIQOLpGLX3WWRfs5FQUKQO7NioLQS0YQdUgh62IFka2zcz/3///8CFAwDAAAAAAAZdqkUs+F8Te+KORSO1vrX3G/r4w3TJMuIrDBXBQAAAAAAGXapFOCok4BjXxi37glUbZYyMry5kkEriKz+BB0AAQMEAQAAAAAAAA=='

#     # expected sig: 3044022012f6a643d1d1a558912e0935dbd6a9694fe87c841e0f699c7cbb7c818503c115022064585f9b69c3452183a74ee7f00ae0452139e2c73b156dfd6ac835bea4fdf975

#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     result = client.sign_psbt(psbt)

#     print(result)


@has_automation("automations/sign_with_wallet_accept.json")
def test_sign_psbt_multisig_wsh(client: Client):
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF/**",
            f"[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK/**",
        ],
    )

    wallet_hmac = bytes.fromhex(
        "d6434852fb3caa7edbd1165084968f1691444b3cfc10cf1e431acbbc7f48451f"
    )

    psbt = open_psbt_from_file(f"{tests_root}/psbt/multisig/wsh-2of2.psbt")

    result = client.sign_psbt(psbt, wallet, wallet_hmac)

    assert result == {
        0: bytes.fromhex(
            "304402206ab297c83ab66e573723892061d827c5ac0150e2044fed7ed34742fedbcfb26e0220319cdf4eaddff63fc308cdf53e225ea034024ef96de03fd0939b6deeea1e8bd301"
        )
    }


# def test_sign_psbt_legacy_wrong_non_witness_utxo(client: Client):
#     # legacy address
#     # PSBT for a legacy 1-input 1-output spend
#     # The spend is valid, but the non-witness utxo is wrong; therefore, it should fail the hash test
#     # TODO: this fails PSBT decoding; need to make a version we can control for this test.

#     unsigned_raw_psbt_base64 = "cHNidP8BAFQCAAAAAbUlIwxFfIt0fsuFCNtL3dHKcOvUPQu2CNcqc8FrNtTyAAAAAAD+////AaDwGQAAAAAAGKkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrAAAAAAAAQD5AgAAAAABATfphYFskBaL7jbWIkU3K7RS5zKr5BvfNHjec1rNieTrAQAAABcWABTkjiMSrvGNi5KFtSy72CSJolzNDv7///8C/y8bAAAAAAAZdqkU2FZEFTTPb1ZpCw2Oa2sc/FxM59GIrDS2GJ0BAAAAF6kUnEFiBqwsbP0pWpazURx45PGdXkWHAkcwRAIgCxWs2+R6UcpQuD6QKydU0irJ7yNe++5eoOly5VgqrEsCIHUD6t4LNW0292vnP+heXZ6Walx8DRW2TB+IOazzDNcaASEDnQS6zdUebuNm7FuOdKonnlNmPPpUyN66w2CIsX5N+pUySC0BAAA="
#     psbt = PSBT()
#     psbt.deserialize(unsigned_raw_psbt_base64)

#     with pytest.raises(IncorrectDataError):
#         client.sign_psbt(psbt)


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_taproot_1to2(client: Client):
    # PSBT for a p2tr 1-input 2-output spend (1 change address)

    psbt = open_psbt_from_file(f"{tests_root}/psbt/singlesig/tr-1to2.psbt")

    wallet = PolicyMapWallet(
        "",
        "tr(@0)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
        ],
    )

    result = client.sign_psbt(psbt, wallet, None)

    # Unlike other transactions, Schnorr signatures are not deterministic (unless the randomness is removed)
    # Therefore, for this testcase we hard-code the sighash (which was validated with Bitcoin Core 22.0 when the
    # transaction was sent), and we verify the produced Schnorr signature with the reference bip340 implementation.

    # sighash verified with bitcoin-core
    sighash0 = bytes.fromhex("7A999E5AD6F53EA6448E7026061D3B4523F957999C430A5A492DFACE74AE31B6")

    # get the (tweaked) pubkey from the scriptPubKey
    pubkey0 = psbt.inputs[0].witness_utxo.scriptPubKey[2:]

    assert len(result) == 1

    # the sighash 0x01 is appended to the signature
    assert len(result[0]) == 64+1
    assert result[0][-1] == 0x01

    sig0 = result[0][:-1]

    assert bip0340.schnorr_verify(sighash0, pubkey0, sig0)


def test_sign_psbt_singlesig_wpkh_4to3(client: Client, comm: SpeculosClient, is_speculos: bool):
    # PSBT for a segwit 4-input 3-output spend (1 change address)
    # this test also checks that addresses, amounts and fees shown on screen are correct

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    n_ins = 4
    n_outs = 3

    in_amounts = [10000 + 10000 * i for i in range(n_ins)]
    out_amounts = [9999 + 9999 * i for i in range(n_outs)]

    change_index = 1

    psbt = txmaker.createPsbt(
        wallet,
        in_amounts,
        out_amounts,
        [i == change_index for i in range(n_outs)]
    )

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    fees_amount = sum_in - sum_out

    all_events: List[dict] = []

    x = threading.Thread(target=ux_thread_sign_psbt, args=[comm, all_events])
    x.start()
    result = client.sign_psbt(psbt, wallet, None)
    x.join()

    assert len(result) == n_ins

    parsed_events = parse_signing_events(all_events)

    assert((parsed_events["fees"] == format_amount(CURRENCY_TICKER, fees_amount)) or
            (parsed_events["fees"] == format_amount(CURRENCY_TICKER_ALT, fees_amount)))

    shown_out_idx = 0
    for out_idx in range(n_outs):
        if out_idx != change_index:
            out_amt = psbt.tx.vout[out_idx].nValue
            assert((parsed_events["amounts"][shown_out_idx] == format_amount(CURRENCY_TICKER, out_amt)) or 
                    (parsed_events["amounts"][shown_out_idx] == format_amount(CURRENCY_TICKER_ALT, out_amt)))

            out_addr = Script(psbt.tx.vout[out_idx].scriptPubKey).address(network=NETWORKS["test"])
            assert parsed_events["addresses"][shown_out_idx] == out_addr

            shown_out_idx += 1


def test_sign_psbt_singlesig_large_amount(client: Client, comm: SpeculosClient, is_speculos: bool):
    # Test with a transaction with an extremely large amount

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    in_amounts = [21_000_000*100_000_000]
    out_amounts = [21_000_000*100_000_000 - 100_000]

    psbt = txmaker.createPsbt(wallet, in_amounts, out_amounts, [False])

    sum_in = sum(in_amounts)
    sum_out = sum(out_amounts)

    assert sum_out < sum_in

    fees_amount = sum_in - sum_out

    all_events: List[dict] = []

    x = threading.Thread(target=ux_thread_sign_psbt, args=[comm, all_events])
    x.start()
    result = client.sign_psbt(psbt, wallet, None)
    x.join()

    assert len(result) == 1

    parsed_events = parse_signing_events(all_events)

    assert((parsed_events["fees"] == format_amount(CURRENCY_TICKER, fees_amount)) or
          (parsed_events["fees"] == format_amount(CURRENCY_TICKER_ALT, fees_amount)))

    out_amt = psbt.tx.vout[0].nValue
    assert((parsed_events["amounts"][0] == format_amount(CURRENCY_TICKER, out_amt)) or
          (parsed_events["amounts"][0] == format_amount(CURRENCY_TICKER_ALT, out_amt)))


@has_automation("automations/sign_with_default_wallet_accept.json")
def test_sign_psbt_singlesig_wpkh_512to256(client: Client, enable_slow_tests: bool):
    # PSBT for a transaction with 512 inputs and 256 outputs (maximum currently supported in the app)
    # Very slow test (esp. with DEBUG enabled), so disabled unless the --enableslowtests option is used

    if not enable_slow_tests:
        pytest.skip()

    n_inputs = 512
    n_outputs = 256

    wallet = PolicyMapWallet(
        "",
        "tr(@0)",
        [
            "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
        ],
    )

    psbt = txmaker.createPsbt(
        wallet,
        [10000 + 10000 * i for i in range(n_inputs)],
        [999 + 99 * i for i in range(n_outputs)],
        [i == 42 for i in range(n_outputs)]
    )

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == n_inputs


def test_sign_psbt_fail_11_changes(client: Client):
    # PSBT for transaction with 11 change addresses; the limit is 10, so it must fail with NotSupportedError
    # before any user interaction

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    psbt = txmaker.createPsbt(
        wallet,
        [11 * 100_000_000 + 1234],
        [100_000_000] * 11,
        [True] * 11,
    )

    with pytest.raises(NotSupportedError):
        client.sign_psbt(psbt, wallet, None)


def test_sign_psbt_fail_wrong_non_witness_utxo(client: Client, is_speculos: bool):
    # PSBT for transaction with the wrong non-witness utxo for an input.
    # It must fail with IncorrectDataError before any user interaction.

    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
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


def test_sign_psbt_with_opreturn(client: Client, comm: SpeculosClient):
    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    psbt_b64 = "cHNidP8BAKMCAAAAAZ0gZDu3l28lrZWbtsuoIfI07zpsaXXMe6sMHHJn03LPAAAAAAD+////AgAAAAAAAAAASGpGVGhlIFRpbWVzIDAzL0phbi8yMDA5IENoYW5jZWxsb3Igb24gYnJpbmsgb2Ygc2Vjb25kIGJhaWxvdXQgZm9yIGJhbmtzLsGVmAAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ8AAAAAAAEAcQIAAAABnpp88I3RXEU5b28rI3GGAXaWkk+w1sEqWDXFXdacKg8AAAAAAP7///8CgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmvNabSkBAAAAFgAUCA6eZPSQK9gnq8ngOSaQ0ZdPeIVBAAAAAQEfgJaYAAAAAAAWABQTR+gqA3tduzjPjEdZ8kKx9cfgmiIGAny3XTSwBcTrn2K78sRX12OOgT51fvzsj6aGd9lQtjZiGPWswv1UAACAAQAAgAAAAIAAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAA=="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    with automation(comm, "automations/sign_with_default_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet, None)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_segwit_v16(client: Client, comm: SpeculosClient):
    # This psbt contains an output with future psbt version 16 (corresponding to address
    # tb1sqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq4hu3px).
    # The app should accept it nonetheless.

    psbt_b64 = "cHNidP8BAH0CAAAAAZvg4s1Yxz9DddwBeI+qqU7hcldqGSgWPXuZZReEFYvKAAAAAAD+////AqdTiQAAAAAAFgAUK5M/aeXrJEofBL7Uno7J5OyTvJ9AQg8AAAAAACJgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAHECAAAAAYWOSCXXmA0ztidPI5A6FskW99o7nWNVeFP7rXND5B9aAAAAAAD+////AoCWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JrzWm0pAQAAABYAFF7XSHCIZoptcIrXIWce1tKqp11EaQAAAAEBH4CWmAAAAAAAFgAUE0foKgN7Xbs4z4xHWfJCsfXH4JoiBgJ8t100sAXE659iu/LEV9djjoE+dX787I+mhnfZULY2Yhj1rML9VAAAgAEAAIAAAACAAAAAAAAAAAAAIgIDGZuJ2DVvV+HOOAoSBc8oYG2+qJhVsRw9/s+4oaUzVokY9azC/VQAAIABAACAAAAAgAEAAAABAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallet = PolicyMapWallet(
        "",
        "wpkh(@0)",
        [
            "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
        ],
    )

    with automation(comm, "automations/sign_with_default_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet, None)

    assert len(hww_sigs) == 1


def test_sign_psbt_with_external_inputs(client: Client, comm: SpeculosClient):
    # PSBT obtained by joining pkh-1to1.psbt, tr-1to2.psbt, wpkh-1to2.psbt.
    # We sign it with each of the respective wallets; therefore it must show the "external inputs" warning each time.
    psbt_b64 = "cHNidP8BAP0yAQIAAAADobgj0jNtaUtJNO+bblt94XoFUT2oop2wKi7Lx6mm/m0BAAAAAP3///9RIsLN5oI+VXVBdbksnFegqOGsg8OOF4f9Oh/zNI6VEwEAAAAA/f///3oqmXlWwJ+Op/0oGcGph7sU4iv5rc2vIKiXY3Is7uJkAQAAAAD9////BaCGAQAAAAAAFgAUE5m4oJhHoDmwNS9Y0hLBgLqxf3dV/6cAAAAAACJRIAuOdIa8MGoK77enwArwQFVC2xrNc+7MqCdxzPX+XrYPeEEPAAAAAAAZdqkUE9fVgWaUbD7AIpNAZtjA0RHRu0GIrHQ4IwAAAAAAFgAU6zj6m4Eo+B8m6V7bDF/66oNpD+Sguw0AAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAABASunhqkAAAAAACJRINj08dGJltthuxyvVCPeJdih7unJUNN+b/oCMBLV5i4NIRYhLqKFalzxEOZqK+nXNTFHk/28s4iyuPE/K2remC569RkA9azC/VYAAIABAACAAAAAgAEAAAAAAAAAARcgIS6ihWpc8RDmaivp1zUxR5P9vLOIsrjxPytq3pguevUAAQCMAgAAAAHsIw5TCVJWBSokKCcO7ASYlEsQ9vHFePQxwj0AmLSuWgEAAAAXFgAUKBU5gg4t6XOuQbpgBLQxySHE2G3+////AnJydQAAAAAAF6kUyLkGrymMcOYDoow+/C+uGearKA+HQEIPAAAAAAAZdqkUy65bUM+Tnm9TG4prer14j+FLApeIrITyHAAiBgLuhgggfiEChCb2nnZEfX49XgdwSfXmg8MTbCMUdipHGBj1rML9LAAAgAEAAIAAAACAAAAAAAAAAAAAAQB9AgAAAAGvv64GWQ90H/GvWbasRhEmM2pMSoLbVT32/vq3N6wz8wEAAAAA/f///wJwEQEAAAAAACIAIP3uRBxW5bBtDfgsEkxwcBSlyhlli+C5hWvKFvHtMln3pfQwAAAAAAAWABQ6+EKa1ZVKpe6KM8mD/YoehnmSSwAAAAABAR+l9DAAAAAAABYAFDr4QprVlUql7oozyYP9ih6GeZJLIgYD7iw9mOsfk8Chqo5aQAm3Dre0Tq0V8WZvE2sBKtWNMGgY9azC/VQAAIABAACAAAAAgAEAAAAIAAAAAAABBSACkIHs5WFqocuZMZ/Eh07+5H8IzrpfYARjbIxDQJpfCiEHApCB7OVhaqHLmTGfxIdO/uR/CM66X2AEY2yMQ0CaXwoZAPWswv1WAACAAQAAgAAAAIABAAAAAgAAAAAAIgICKexHcnEx7SWIogxG7amrt9qm9J/VC6/nC5xappYcTswY9azC/VQAAIABAACAAAAAgAEAAAAKAAAAAAA="
    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    wallets = [
        PolicyMapWallet(
            "",
            "pkh(@0)",
            [
                "[f5acc2fd/44'/1'/0']tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT/**"
            ],
        ),
        PolicyMapWallet(
            "",
            "tr(@0)",
            [
                "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U/**"
            ],
        ),
        PolicyMapWallet(
            "",
            "wpkh(@0)",
            [
                "[f5acc2fd/84'/1'/0']tpubDCtKfsNyRhULjZ9XMS4VKKtVcPdVDi8MKUbcSD9MJDyjRu1A2ND5MiipozyyspBT9bg8upEp7a8EAgFxNxXn1d7QkdbL52Ty5jiSLcxPt1P/**"
            ],
        )
    ]

    for wallet in wallets:
        with automation(comm, "automations/sign_with_wallet_external_inputs_accept.json"):
            hww_sigs = client.sign_psbt(psbt, wallet, None)

        assert len(hww_sigs) == 1
