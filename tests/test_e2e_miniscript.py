import pytest

from typing import List, Union

import hmac
from hashlib import sha256
from decimal import Decimal

from bip32 import BIP32

from bitcoin_client.ledger_bitcoin import Client
from bitcoin_client.ledger_bitcoin.client_base import TransportClient
from bitcoin_client.ledger_bitcoin.exception.errors import IncorrectDataError, NotSupportedError
from bitcoin_client.ledger_bitcoin.psbt import PSBT
from bitcoin_client.ledger_bitcoin.wallet import PolicyMapWallet

from test_utils import SpeculosGlobals

from speculos.client import SpeculosClient
from test_utils.speculos import automation

from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, testnet_to_regtest_addr as T
from .conftest import AuthServiceProxy


def get_internal_xpub(speculos_globals: SpeculosGlobals, path: str) -> str:
    bip32 = BIP32.from_seed(speculos_globals.seed, network="test")
    return bip32.get_xpub_from_path(f"m/{path}")


def run_test_e2e(wallet_policy: PolicyMapWallet, rpc: AuthServiceProxy, rpc_test_wallet: AuthServiceProxy, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
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
        },
        options={
            # make sure that the fee is large enough; it looks like
            # fee estimation doesn't work in core with miniscript, yet
            "fee_rate": 10
        })

    psbt_b64 = result["psbt"]

    # ==> sign it with the hww

    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    with automation(comm, "automations/sign_with_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet_policy, wallet_hmac)

    assert len(hww_sigs) == len(psbt.inputs)  # should be true as long as all inputs are internal


def run_test_invalid(client: Client, policy_map: str, keys_info: List[str]):
    wallet_policy = PolicyMapWallet(
        name="Invalid wallet",
        policy_map=policy_map,
        keys_info=keys_info)

    with pytest.raises((IncorrectDataError, NotSupportedError)):
        client.register_wallet(wallet_policy)


def test_e2e_miniscript_one_of_two_1(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of two keys (equally likely)
    # or(pk(key_1),pk(key_2))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    wallet_policy = PolicyMapWallet(
        name="Joint account",
        policy_map="wsh(or_b(pk(@0),s:pk(@1)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
            f"{core_xpub_orig}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_one_of_two_2(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # One of two keys (one likely, one unlikely)
    # or(99@pk(key_likely),pk(key_unlikely))

    path = "499'/1'/0'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    wallet_policy = PolicyMapWallet(
        name="Joint account",
        policy_map="wsh(or_d(pk(@0),pkh(@1)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
            f"{core_xpub_orig}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_2fa(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    # and(pk(key_user),or(99@pk(key_service),older(12960)))

    path = "48'/1'/0'/2'"
    _, core_xpub_orig = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    wallet_policy = PolicyMapWallet(
        name="2FA wallet",
        policy_map="wsh(and_v(v:pk(@0),or_d(pk(@1),older(12960))))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
            f"{core_xpub_orig}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_decaying_3of3(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # A user and a 2FA service need to sign off, but after 90 days the user alone is enough
    # thresh(3,pk(key_1),pk(key_2),pk(key_3),older(12960))

    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    wallet_policy = PolicyMapWallet(
        name="Decaying 3of3",
        policy_map="wsh(thresh(3,pk(@0),s:pk(@1),s:pk(@2),sln:older(12960)))",
        keys_info=[
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
            f"{core_xpub_orig1}/**",
            f"{core_xpub_orig2}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_bolt3_offered_htlc(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # The BOLT #3 offered HTLC policy
    # or(pk(key_revocation),and(pk(key_remote),or(pk(key_local),hash160(H))))

    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    H = "395e368b267d64945f30e4b71de1054f364c9473"  # random
    wallet_policy = PolicyMapWallet(
        name="BOLT #3 offered",
        policy_map=f"wsh(t:or_c(pk(@0),and_v(v:pk(@1),or_c(pk(@2),v:hash160({H})))))",
        keys_info=[
            f"{core_xpub_orig1}/**",
            f"{core_xpub_orig2}/**",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_bolt3_received_htlc(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    # The BOLT #3 received HTLC policy
    # andor(pk(key_remote),or_i(and_v(v:pkh(key_local),hash160(H)),older(1008)),pk(key_revocation))

    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    H = "395e368b267d64945f30e4b71de1054f364c9473"  # random
    wallet_policy = PolicyMapWallet(
        name="BOLT #3 received",
        policy_map=f"wsh(andor(pk(@0),or_i(and_v(v:pkh(@1),hash160({H})),older(1008)),pk(@2)))",
        keys_info=[
            f"{core_xpub_orig1}/**",
            f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**",
            f"{core_xpub_orig2}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_e2e_miniscript_me_or_3of5(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, comm: Union[TransportClient, SpeculosClient]):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()
    _, core_xpub_orig5 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**"

    wallet_policy = PolicyMapWallet(
        name="Me or them",
        policy_map=f"wsh(or_d(pk(@0),multi(3,@1,@2,@3,@4,@5)))",
        keys_info=[
            internal_xpub_orig,
            f"{core_xpub_orig1}/**",
            f"{core_xpub_orig2}/**",
            f"{core_xpub_orig3}/**",
            f"{core_xpub_orig4}/**",
            f"{core_xpub_orig5}/**",
        ])

    run_test_e2e(wallet_policy, rpc, rpc_test_wallet, client, speculos_globals, comm)


def test_invalid_miniscript(rpc, client: Client, speculos_globals: SpeculosGlobals):
    path = "48'/1'/0'/2'"
    _, core_xpub_orig1 = create_new_wallet()
    _, core_xpub_orig2 = create_new_wallet()
    _, core_xpub_orig3 = create_new_wallet()
    _, core_xpub_orig4 = create_new_wallet()
    _, core_xpub_orig5 = create_new_wallet()
    internal_xpub = get_internal_xpub(speculos_globals, path)
    internal_xpub_orig = f"[{speculos_globals.master_key_fingerprint.hex()}/{path}]{internal_xpub}/**"

    # sh(sh(...)), wsh(sh(...)), wsh(wsh(...)) are invalid
    run_test_invalid(client, "sh(sh(pkh(@0)))", [internal_xpub_orig])
    run_test_invalid(client, "wsh(sh(pkh(@0)))", [internal_xpub_orig])
    run_test_invalid(client, "wsh(wsh(pkh(@0)))", [internal_xpub_orig])

    # tr must be top-level
    run_test_invalid(client, "wsh(tr(pk(@0)))", [internal_xpub_orig])
    run_test_invalid(client, "sh(tr(pk(@0)))", [internal_xpub_orig])

    # valid miniscript must be inside wsh() or sh(wsh())
    run_test_invalid(client, "or_d(pk(@0),pkh(@1))", [internal_xpub_orig, core_xpub_orig1])
    run_test_invalid(client, "sh(or_d(pk(@0),pkh(@1)))", [internal_xpub_orig, core_xpub_orig1])

    # sortedmulti is not valid miniscript, can only be used as a descriptor inside sh or wsh
    run_test_invalid(client, "wsh(or_d(pk(@0),sortedmulti(3,@1,@2,@3,@4,@5)))",
                     [
                         internal_xpub_orig,
                         f"{core_xpub_orig1}/**",
                         f"{core_xpub_orig2}/**",
                         f"{core_xpub_orig3}/**",
                         f"{core_xpub_orig4}/**",
                         f"{core_xpub_orig5}/**",
                     ])
