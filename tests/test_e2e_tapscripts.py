import pytest

from typing import List, Union

import hmac
from hashlib import sha256
from decimal import Decimal

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.client_base import TransportClient
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from bitcoin_client.ledger_bitcoin.psbt import PSBT
from bitcoin_client.ledger_bitcoin.wallet import WalletPolicy

from test_utils import SpeculosGlobals, get_internal_xpub, count_internal_keys

from speculos.client import SpeculosClient
from test_utils.speculos import automation

from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, testnet_to_regtest_addr as T
from .conftest import AuthServiceProxy


def run_test_e2e(wallet_policy: WalletPolicy, core_wallet_names: List[str], rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    with automation(comm, "automations/register_wallet_accept.json"):
        wallet_id, wallet_hmac = client.register_wallet(wallet_policy)

    assert wallet_id == wallet_policy.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

    address_hww = client.get_wallet_address(wallet_policy, wallet_hmac, 0, 3, False)

    # ==> verify the address matches what bitcoin-core computes
    receive_descriptor = wallet_policy.get_descriptor(change=False)
    receive_descriptor_info = rpc.getdescriptorinfo(receive_descriptor)
    # bitcoin-core adds the checksum, and requires it for other calls
    receive_descriptor_chk = receive_descriptor_info["descriptor"]
    address_core = rpc.deriveaddresses(receive_descriptor_chk, [3, 3])[0]

    assert T(address_hww) == address_core

    # also get the change descriptor for later
    change_descriptor = wallet_policy.get_descriptor(change=True)
    change_descriptor_info = rpc.getdescriptorinfo(change_descriptor)
    change_descriptor_chk = change_descriptor_info["descriptor"]

    # ==> import wallet in bitcoin-core

    multisig_wallet_name = get_unique_wallet_name()
    rpc.createwallet(
        wallet_name=multisig_wallet_name,
        disable_private_keys=True,
        descriptors=True,
    )
    multisig_rpc = get_wallet_rpc(multisig_wallet_name)
    multisig_rpc.importdescriptors([{
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

    # ==> fund the multisig wallet and get prevout info

    rpc_test_wallet.sendtoaddress(T(address_hww), "0.1")
    generate_blocks(1)

    assert multisig_rpc.getwalletinfo()["balance"] == Decimal("0.1")

    # ==> prepare a psbt spending from the wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = multisig_rpc.walletcreatefundedpsbt(
        outputs={
            out_address: Decimal("0.01")
        }
    )

    psbt_b64 = result["psbt"]

    # ==> sign it with the hww

    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    with automation(comm, "automations/sign_with_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet_policy, wallet_hmac)

    # only correct for taproot policies
    for i, part_sig in hww_sigs:
        if part_sig.tapleaf_hash is not None:
            # signature for a script spend
            psbt.inputs[i].tap_script_sigs[(part_sig.pubkey, part_sig.tapleaf_hash)] = part_sig.signature
        else:
            # key path spend
            psbt.inputs[i].tap_key_sig = part_sig.signature

    signed_psbt_hww_b64 = psbt.serialize()

    n_internal_keys = count_internal_keys(speculos_globals.seed, "test", wallet_policy)
    assert len(hww_sigs) == n_internal_keys * len(psbt.inputs)  # should be true as long as all inputs are internal

    # ==> sign it with bitcoin-core

    partial_psbts = [signed_psbt_hww_b64]
    for core_wallet_name in core_wallet_names:
        partial_psbt_response = get_wallet_rpc(core_wallet_name).walletprocesspsbt(psbt_b64)
        partial_psbts.append(partial_psbt_response["psbt"])

    # ==> finalize the psbt, extract tx and broadcast
    combined_psbt = rpc.combinepsbt(partial_psbts)
    result = rpc.finalizepsbt(combined_psbt)

    assert result["complete"] == True
    rawtx = result["hex"]

    # make sure the transaction is valid by broadcasting it (would fail if rejected)
    rpc.sendrawtransaction(rawtx)


def run_test_invalid(client: Client, descriptor_template: str, keys_info: List[str]):
    wallet_policy = WalletPolicy(
        name="Invalid wallet",
        descriptor_template=descriptor_template,
        keys_info=keys_info)

    with pytest.raises((IncorrectDataError, NotSupportedError)):
        client.register_wallet(wallet_policy)


def test_e2e_tapscript_one_of_two_keypath(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of two keys, with the foreign key in the key path spend
    # tr(my_key,pk(foreign_key_1))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-2",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig}",
        ])

    run_test_e2e(wallet_policy, [], rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_one_of_two_scriptpath(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of two keys, with the foreign key in the key path spend
    # tr(foreign_key,pk(my_key))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-2",
        descriptor_template="tr(@0/**,pk(@1/**))",
        keys_info=[
            f"{core_xpub_orig}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
        ])

    run_test_e2e(wallet_policy, [], rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_one_of_three_keypath(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of three keys, with the internal one in the key-path spend
    # tr(my_key,{pk(foreign_key_1,foreign_key_2)})

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-3",
        descriptor_template="tr(@0/**,{pk(@1/**),pk(@2/**)})",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_1}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(wallet_policy, [],
                 rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_one_of_three_scriptpath(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of three keys, with the internal one in on of the scripts
    # tr(foreign_key_1,{pk(my_key,foreign_key_2)})

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    _, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1-of-3",
        descriptor_template="tr(@0/**,{pk(@1/**),pk(@2/**)})",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(wallet_policy, [],
                 rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_multi_a_2of2(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # tr(foreign_key_1,multi_a(2,my_key,foreign_key_2))

    path = "499'/1'/0'"
    _, core_xpub_orig_1 = create_new_wallet()
    core_wallet_name2, core_xpub_orig_2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    wallet_policy = WalletPolicy(
        name="Tapscript 1 or 2-of-2",
        descriptor_template="tr(@0/**,multi_a(2,@1/**,@2/**))",
        keys_info=[
            f"{core_xpub_orig_1}",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}",
            f"{core_xpub_orig_2}",
        ])

    run_test_e2e(wallet_policy, [core_wallet_name2],
                 rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_depth4(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # A taproot tree with maximum supported depth, where the internal key is in the deepest script

    keys_info = []
    for _ in range(4):
        _, core_xpub_orig = create_new_wallet()
        keys_info.append(core_xpub_orig)

    path = "499'/1'/0'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)
    keys_info.append(f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}")

    wallet_policy = WalletPolicy(
        name="Tapscriptception",
        descriptor_template="tr(@0/**,{pk(@1/**),{pk(@2/**),{pk(@3/**),pk(@4/**)}}})",
        keys_info=keys_info)

    run_test_e2e(wallet_policy, [], rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_tapscript_large(rpc, rpc_test_wallet, client: Client, speculos_globals:
                             SpeculosGlobals, comm: Union[TransportClient, SpeculosClient], model: str):
    # A quite large tapscript with 8 tapleaves and 22 keys in total.

    # Takes more memory than Nano S can handle
    if (model == "nanos"):
        pytest.skip("Not supported on Nano S due to memory limitations")

    keys_info = []

    core_wallet_name = None
    for i in range(21):
        core_wallet_name_i, core_xpub_orig = create_new_wallet()
        if i == 9:
            # sign with bitcoin-core using the ninth external key (it will be key @10 in the policy)
            core_wallet_name = core_wallet_name_i
        keys_info.append(core_xpub_orig)

    path = "499'/1'/0'"
    internal_xpub = get_internal_xpub(speculos_globals.seed, path)

    # the internal key is key @9, in a 2-of-4 multisig
    keys_info.insert(9, f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}")

    wallet_policy = WalletPolicy(
        name="Tapzilla",
        descriptor_template="tr(@0/**,{{{sortedmulti_a(1,@1/**,@2/**,@3/**,@4/**,@5/**),multi_a(2,@6/**,@7/**,@8/**)},{multi_a(2,@9/**,@10/**,@11/**,@12/**),pk(@13/**)}},{{multi_a(2,@14/**,@15/**),multi_a(3,@16/**,@17/**,@18/**)},{multi_a(2,@19/**,@20/**),pk(@21/**)}}})",
        keys_info=keys_info)

    run_test_e2e(wallet_policy, [core_wallet_name], rpc, rpc_test_wallet, client, speculos_globals, comm)
