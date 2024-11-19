import pytest

from typing import Dict, List, Tuple

import hmac
from hashlib import sha256
from decimal import Decimal

from ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from ledger_bitcoin.exception.device_exception import DeviceException
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.wallet import WalletPolicy
from ledger_bitcoin import MusigPubNonce, MusigPartialSignature, PartialSignature, SignPsbtYieldedObject

from test_utils import SpeculosGlobals, bip0327, get_internal_xpub, count_internal_key_placeholders
from test_utils.musig2 import PsbtMusig2Cosigner

from ragger_bitcoin import RaggerClient
from ragger_bitcoin.ragger_instructions import Instructions
from ragger.navigator import Navigator
from ragger.firmware import Firmware
from ragger.error import ExceptionRAPDU

from .instructions import e2e_register_wallet_instruction, e2e_sign_psbt_instruction

from .conftest import AuthServiceProxy, create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, import_descriptors_with_privkeys, testnet_to_regtest_addr as T


def run_test_e2e_musig2(navigator: Navigator, client: RaggerClient, wallet_policy: WalletPolicy, core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy, speculos_globals: SpeculosGlobals,
                        instructions_register_wallet: Instructions,
                        instructions_sign_psbt: Instructions, test_name: str):
    # TODO: delete
    def printb(*args):
        print('\033[94m', end='')
        print(*args)
        print('\033[0m', end='')

    wallet_id, wallet_hmac = client.register_wallet(wallet_policy, navigator,
                                                    instructions=instructions_register_wallet, testname=f"{test_name}_register")

    assert wallet_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key,
                 wallet_id, sha256).digest(),
        wallet_hmac,
    )

    address_hww = client.get_wallet_address(
        wallet_policy, wallet_hmac, 0, 3, False)

    # ==> verify the address matches what bitcoin-core computes
    receive_descriptor = wallet_policy.get_descriptor(change=False)
    receive_descriptor_info = rpc.getdescriptorinfo(receive_descriptor)
    # bitcoin-core adds the checksum, and requires it for other calls
    receive_descriptor_chk: str = receive_descriptor_info["descriptor"]
    address_core = rpc.deriveaddresses(receive_descriptor_chk, [3, 3])[0]

    assert T(address_hww) == address_core

    # also get the change descriptor for later
    change_descriptor = wallet_policy.get_descriptor(change=True)
    change_descriptor_info = rpc.getdescriptorinfo(change_descriptor)
    change_descriptor_chk: str = change_descriptor_info["descriptor"]

    printb("Receive descriptor:", receive_descriptor_chk)  # TODO: remove
    printb("Change descriptor:", change_descriptor_chk)  # TODO: remove

    # ==> import wallet in bitcoin-core

    new_core_wallet_name = get_unique_wallet_name()
    rpc.createwallet(
        wallet_name=new_core_wallet_name,
        disable_private_keys=True,
        descriptors=True,
    )
    core_wallet_rpc = get_wallet_rpc(new_core_wallet_name)

    core_wallet_rpc.importdescriptors([{
        "desc": receive_descriptor_chk,
        "active": True,
        "internal": False,
        "timestamp": "now"
    }, {
        "desc": change_descriptor_chk,
        "active": True,
        "internal": True,
        "timestamp": "now"
    }])

    # ==> fund the wallet and get prevout info

    rpc_test_wallet.sendtoaddress(T(address_hww), "0.1")
    generate_blocks(1)

    assert core_wallet_rpc.getwalletinfo()["balance"] == Decimal("0.1")

    # ==> prepare a psbt spending from the wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = core_wallet_rpc.walletcreatefundedpsbt(
        outputs={
            out_address: Decimal("0.01")
        },
        options={
            # We need a fixed position to be able to know how to navigate in the flows
            "changePosition": 1
        }
    )

    # ==> import descriptor for each bitcoin-core wallet
    for core_wallet_name in core_wallet_names:
        import_descriptors_with_privkeys(
            core_wallet_name, receive_descriptor_chk, change_descriptor_chk)

    psbt_b64 = result["psbt"]

    printb("PSBT before the first round:")
    printb(psbt_b64)

    # Round 1: get nonces

    # ==> get nonce from the hww

    n_internal_keys = count_internal_key_placeholders(
        speculos_globals.seed, "test", wallet_policy)

    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    hww_yielded: List[Tuple[int, SignPsbtYieldedObject]] = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator,
                                                                            instructions=instructions_sign_psbt,
                                                                            testname=f"{test_name}_sign")

    printb("SignPsbt yielded:", hww_yielded)
    for (input_index, yielded) in hww_yielded:
        if isinstance(yielded, MusigPubNonce):
            printb(f"Yielded MusigPubNonce for input {input_index}:")
            printb(yielded.participant_pubkey.hex(), yielded.aggregate_pubkey.hex(
            ), None if yielded.tapleaf_hash is None else yielded.tapleaf_hash.hex())
            psbt_key = (
                yielded.participant_pubkey,
                yielded.aggregate_pubkey,
                yielded.tapleaf_hash
            )

            assert len(yielded.aggregate_pubkey) == 33

            psbt.inputs[input_index].musig2_pub_nonces[psbt_key] = yielded.pubnonce
        elif isinstance(yielded, PartialSignature):
            # depending on the policy, a PartialSignature might be returned
            pass
        else:
            # We don't expect a MusigPartialSignature here
            raise ValueError(
                f"sign_psbt yielded an unexpected object for input {input_index}:", yielded)

            # should be true as long as all inputs are internal
    assert len(hww_yielded) == n_internal_keys * len(psbt.inputs)

    signed_psbt_hww_b64 = psbt.serialize()

    printb("PSBT after the first round for the hww:", signed_psbt_hww_b64)

    # ==> Process it with bitcoin-core to get the musig pubnonces
    partial_psbts = [signed_psbt_hww_b64]

    # partial_psbts = []

    for core_wallet_name in core_wallet_names:
        printb("Processing for:", core_wallet_name)
        psbt_res = get_wallet_rpc(
            core_wallet_name).walletprocesspsbt(psbt_b64)["psbt"]
        printb("PSBT processed by core:")
        printb(psbt_res)
        partial_psbts.append(psbt_res)

    combined_psbt = rpc.combinepsbt(partial_psbts)

    # Round 2: get Musig Partial Signatures

    printb(wallet_policy.get_descriptor(None))

    # TODO: should now do the second round
    printb("PSBT after the first round:", combined_psbt)

    printb("Starting round 2")

    psbt = PSBT()
    psbt.deserialize(combined_psbt)

    hww_yielded: List[Tuple[int, SignPsbtYieldedObject]] = client.sign_psbt(psbt, wallet_policy, wallet_hmac, navigator,
                                                                            instructions=instructions_sign_psbt,
                                                                            testname=f"{test_name}_sign")

    printb("SignPsbt yielded:", hww_yielded)
    for (input_index, yielded) in hww_yielded:
        if isinstance(yielded, MusigPartialSignature):
            psbt_key = (
                yielded.participant_pubkey,
                yielded.aggregate_pubkey,
                yielded.tapleaf_hash
            )

            assert len(yielded.aggregate_pubkey) == 33

            psbt.inputs[input_index].musig2_partial_sigs[psbt_key] = yielded.partial_signature
        elif isinstance(yielded, PartialSignature):
            # depending on the policy, a PartialSignature might be returned
            pass
        else:
            # We don't expect a MusigPubNonce here, we should be in the second round
            raise ValueError(
                f"sign_psbt yielded an unexpected object for input {input_index}:", yielded)

    # should be true as long as all inputs are internal
    assert len(hww_yielded) == n_internal_keys * len(psbt.inputs)

    signed_psbt_hww_b64 = psbt.serialize()

    printb("PSBT after the second round for the hww:", signed_psbt_hww_b64)

    # ==> Get Musig partial signatures with each bitcoin-core wallet

    partial_psbts = [signed_psbt_hww_b64]
    for core_wallet_name in core_wallet_names:
        printb("Processing for:", core_wallet_name)
        psbt_res = get_wallet_rpc(
            core_wallet_name).walletprocesspsbt(combined_psbt)["psbt"]
        printb("PSBT processed by core:")
        printb(psbt_res)
        partial_psbts.append(psbt_res)

    # ==> finalize the psbt, extract tx and broadcast
    combined_psbt = rpc.combinepsbt(partial_psbts)
    result = rpc.finalizepsbt(combined_psbt)

    assert result["complete"] == True
    rawtx = result["hex"]

    # make sure the transaction is valid by broadcasting it (would fail if rejected)
    rpc.sendrawtransaction(rawtx)


def run_test_invalid(client: RaggerClient, descriptor_template: str, keys_info: List[str]):
    wallet_policy = WalletPolicy(
        name="Invalid wallet",
        descriptor_template=descriptor_template,
        keys_info=keys_info)

    with pytest.raises(ExceptionRAPDU) as e:
        client.register_wallet(wallet_policy)
    assert DeviceException.exc.get(e.value.status) == IncorrectDataError or DeviceException.exc.get(
        e.value.status) == NotSupportedError


def test_e2e_musig2_keypath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                            test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name, core_xpub_orig = create_new_wallet()
    wallet_policy = WalletPolicy(
        name="Musig 2 my ears",
        descriptor_template="tr(musig(@0,@1)/**)",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                               test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name, core_xpub_orig = create_new_wallet()

    # In this policy, the keypath is unspendable

    wallet_policy = WalletPolicy(
        name="Musig 2 my ears",
        descriptor_template="tr(@0/**,pk(musig(@1,@2)/**))",
        keys_info=[
            "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig2_3of3keypath_decaying_scriptpath(navigator: Navigator, firmware: Firmware, client: RaggerClient,
                                                    test_name: str, rpc, rpc_test_wallet, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    core_wallet_name_1, core_xpub_orig_1 = create_new_wallet()
    core_wallet_name_2, core_xpub_orig_2 = create_new_wallet()

    wallet_policy = WalletPolicy(
        name="3-of-3-to-2-of-3",
        descriptor_template="tr(musig(@0,@1,@2)/**,and_v(v:multi_a(2,@0/**,@1/**,@2/**),older(12960)))",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e_musig2(navigator, client, wallet_policy, [core_wallet_name_1, core_wallet_name_2], rpc, rpc_test_wallet, speculos_globals,
                        e2e_register_wallet_instruction(firmware, wallet_policy.n_keys), e2e_sign_psbt_instruction(firmware), test_name)


def test_e2e_musig_invalid(client: RaggerClient, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    text_xpub_1 = "tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}"

    # Some of these tests are for script syntax that is not currently supported in wallet policies.
    # Still worth adding the tests, as they should stay invalid even if such syntax is supported in the future.

    two_keys = [internal_xpub_orig, text_xpub_1]

    # no musig solo
    run_test_invalid(client, "tr(musig(@0)/**))", [internal_xpub_orig])

    # Invalid per BIP-390
    run_test_invalid(client, "pk(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "pkh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "wpkh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "combo(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(wpkh(musig(@0,@1)/**))", two_keys)
    run_test_invalid(client, "sh(wsh(musig(@0,@1)/**))", two_keys)
    run_test_invalid(client, "wsh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(musig(@0,@1)/**)", two_keys)
    run_test_invalid(client, "sh(musig(@0/**,@1/**)/**)", two_keys)

    # nonsensical
    run_test_invalid(client, "musig(@0,@1)/**", two_keys)

    # Invalid per BIP-388
    run_test_invalid(client, "tr(musig(@0,@0,@1)/**))", two_keys)
    run_test_invalid(  # repeated musig() placeholders
        client, "tr(musig(@0,@1)/**,pk(musig(@1,@0)/**))", two_keys)
    run_test_invalid(client, "tr(musig(@0,@1))", two_keys)

    # supported in BIP-390, not in BIP-388
    run_test_invalid(client, "tr(musig(@0/**,@1/**))",  two_keys)
