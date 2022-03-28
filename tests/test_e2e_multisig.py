import pytest

from typing import Dict
import hmac
from hashlib import sha256
from decimal import Decimal

from bip32 import BIP32

from bitcoin_client.ledger_bitcoin import Client, MultisigWallet, AddressType
from bitcoin_client.ledger_bitcoin.psbt import PSBT
from bitcoin_client.ledger_bitcoin._script import is_p2sh, is_p2wsh, parse_multisig

from test_utils import SpeculosGlobals

from speculos.client import SpeculosClient
from test_utils.speculos import automation

from .conftest import create_new_wallet, generate_blocks, get_unique_wallet_name, get_wallet_rpc, testnet_to_regtest_addr as T


def extract_our_pubkeys(psbt: PSBT, master_fp: bytes) -> Dict[int, bytes]:
    # It only works for standard wallets and simple multisig; won't generalize to miniscript
    # based on code in bitcoin-core/HWI

    psbt2 = PSBT()
    psbt2.deserialize(psbt.serialize())
    if (psbt2.version is None or psbt.version == 0):
        psbt2.convert_to_v2()

    pubkeys: Dict[int, bytes] = {}
    for input_num, psbt_in in enumerate(psbt2.inputs):
        utxo = None
        scriptcode = b""
        if psbt_in.witness_utxo:
            utxo = psbt_in.witness_utxo
        if psbt_in.non_witness_utxo:
            assert psbt_in.prev_out is not None
            utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
        if utxo is None:
            continue
        scriptcode = utxo.scriptPubKey

        if is_p2sh(scriptcode):
            if len(psbt_in.redeem_script) == 0:
                continue
            scriptcode = psbt_in.redeem_script

        # Check if P2WSH
        if is_p2wsh(scriptcode):
            if len(psbt_in.witness_script) == 0:
                continue
            scriptcode = psbt_in.witness_script

        multisig = parse_multisig(scriptcode)
        if multisig is not None:
            _, ms_pubkeys = multisig

            our_keys = 0
            for pub in ms_pubkeys:
                if pub in psbt_in.hd_keypaths:
                    pk_origin = psbt_in.hd_keypaths[pub]
                    if pk_origin.fingerprint == master_fp:
                        our_keys += 1
                        pubkeys[input_num] = pub

            if our_keys > 1:
                raise ValueError("Cannot have more than 1 internal key in a supported wallet")
        else:
            for key, origin in psbt_in.hd_keypaths.items():
                if origin.fingerprint == master_fp:
                    pubkeys[input_num] = key

            for key, (_, origin) in psbt_in.tap_bip32_paths.items():
                if key == psbt_in.tap_internal_key and origin.fingerprint == master_fp:
                    pubkeys[input_num] = key
    return pubkeys


def test_e2e_multisig(rpc, rpc_test_wallet, client: Client, speculos_globals: SpeculosGlobals, is_speculos: bool, comm: SpeculosClient):
    if not is_speculos:
        pytest.skip("Requires speculos")

    wallet_name, core_xpub_orig = create_new_wallet()
    wallet_rpc = get_wallet_rpc(wallet_name)

    bip32 = BIP32.from_seed(speculos_globals.seed, network="test")
    internal_xpub = bip32.get_xpub_from_path("m/48'/1'/0'/2'")
    wallet = MultisigWallet(
        name="Cold storage",
        address_type=AddressType.WIT,
        threshold=2,
        keys_info=[
            f"{core_xpub_orig}/**",
            f"[{speculos_globals.master_key_fingerprint.hex()}/48'/1'/0'/2']{internal_xpub}/**",
        ],
    )

    with automation(comm, "automations/register_wallet_accept.json"):
        wallet_id, wallet_hmac = client.register_wallet(wallet)

    assert wallet_id == wallet.id

    assert hmac.compare_digest(
        hmac.new(speculos_globals.wallet_registration_key, wallet_id, sha256).digest(),
        wallet_hmac,
    )

    address_hww = client.get_wallet_address(wallet, wallet_hmac, 0, 3, False)

    # ==> verify the address matches what bitcoin-core computes
    receive_descriptor = wallet.get_descriptor(change=False)
    receive_descriptor_info = rpc.getdescriptorinfo(receive_descriptor)
    # bitcoin-core adds the checksum, and requires it for other calls
    receive_descriptor_chk = receive_descriptor_info["descriptor"]
    address_core = rpc.deriveaddresses(receive_descriptor_chk, [3, 3])[0]

    assert T(address_hww) == address_core

    # also get the change descriptor for later
    change_descriptor = wallet.get_descriptor(change=True)
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

    # ==> prepare a psbt spending from the multisig wallet

    out_address = rpc_test_wallet.getnewaddress()

    result = multisig_rpc.walletcreatefundedpsbt(outputs={
        out_address: Decimal("0.01")
    })

    psbt_b64 = result["psbt"]

    # ==> sign it with the hww

    psbt = PSBT()
    psbt.deserialize(psbt_b64)

    with automation(comm, "automations/sign_with_wallet_accept.json"):
        hww_sigs = client.sign_psbt(psbt, wallet, wallet_hmac)

    assert len(hww_sigs) == len(psbt.inputs)  # should be true as long as all inputs are internal

    for i, pubkey, sig in hww_sigs:
        psbt.inputs[i].partial_sigs[pubkey] = sig

    signed_psbt_hww_b64 = psbt.serialize()

    # ==> sign it with bitcoin-core

    signed_psbt_core_b64 = wallet_rpc.walletprocesspsbt(psbt_b64)["psbt"]

    # ==> finalize the psbt, extract tx and broadcast
    combined_psbt = rpc.combinepsbt([signed_psbt_hww_b64, signed_psbt_core_b64])
    result = rpc.finalizepsbt(combined_psbt)
    rawtx = result["hex"]
    assert result["complete"] == True

    # make sure the transaction is valid by broadcasting it (would fail if rejected)
    rpc.sendrawtransaction(rawtx)
