# This module contains a utility function to create test PSBTs spending from an arbitrary wallet policy.
# It creates transactions spending non-existing UTXOs, and fills in the PSBTs with enough information to
# satisfy the requirements of the Ledger bitcoin app.
# It does not guarantee BIP-174 compliant PSBTs, as some fields that are not required in the
# Ledger bitcoin app might not be filled in.


from io import BytesIO
from random import randint

from typing import List, Tuple, Optional, Union
from bitcoin_client.ledger_bitcoin import WalletPolicy, WalletType
from bitcoin_client.ledger_bitcoin.key import ExtendedKey, KeyOriginInfo, parse_path, get_taproot_output_key
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CScriptWitness, CTransaction, CTxIn, CTxInWitness, CTxOut, COutPoint, CTxWitness, uint256_from_str

from embit.descriptor import Descriptor
from embit.script import Script
from embit.bip32 import HDKey
from embit.bip39 import mnemonic_to_seed

from ledger_bitcoin.embit.descriptor.miniscript import Miniscript
from test_utils import bip0340
from test_utils.wallet_policy import DescriptorTemplate, KeyPlaceholder, PlainKeyPlaceholder, TrDescriptorTemplate, WshDescriptorTemplate, derive_plain_descriptor, tapleaf_hash


SPECULOS_SEED = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
master_key = HDKey.from_seed(mnemonic_to_seed(SPECULOS_SEED))
master_key_fpr = master_key.derive("m/0'").fingerprint


def random_numbers_with_sum(n: int, s: int) -> List[int]:
    """Returns a list of n random numbers with sum s."""
    assert n > 1

    separators = list(sorted([randint(0, s) for _ in range(n - 1)]))
    return [
        separators[0],
        *[separators[i + 1] - separators[i]
            for i in range(len(separators) - 1)],
        s - separators[-1]
    ]


def random_bytes(n: int) -> bytes:
    """Returns n random bytes. Not cryptographically secure."""
    return bytes([randint(0, 255) for _ in range(n)])


def random_txid() -> bytes:
    """Returns 32 random bytes. Not cryptographically secure."""
    return random_bytes(32)


def random_p2tr() -> bytes:
    """Returns 32 random bytes. Not cryptographically secure."""
    privkey = random_bytes(32)
    pubkey = bip0340.point_mul(bip0340.G, int.from_bytes(privkey, 'big'))

    return b'\x51\x20' + (pubkey[0]).to_bytes(32, 'big')


def getScriptPubkeyFromWallet(wallet: WalletPolicy, change: bool, address_index: int) -> Script:
    descriptor_str = wallet.descriptor_template

    # Iterate in reverse order, as strings identifying a small-index key (like @1) can be a
    # prefix of substrings identifying a large-index key (like @12), but not the other way around
    # A more structural parsing would be more robust
    for i, key_info_str in reversed(list(enumerate(wallet.keys_info))):
        if wallet.version == WalletType.WALLET_POLICY_V1 and key_info_str[-3:] != "/**":
            raise ValueError("All the keys must have wildcard (/**)")

        if f"@{i}" not in descriptor_str:
            raise ValueError(f"Invalid policy: not using key @{i}")

        descriptor_str = descriptor_str.replace(f"@{i}", key_info_str)

    # by doing the text substitution of '/**' at the end, this works for either V1 or V2
    descriptor_str = descriptor_str.replace("/**", f"/{1 if change else 0}/*")

    return Descriptor.from_string(descriptor_str).derive(address_index).script_pubkey()


def createFakeWalletTransaction(n_inputs: int, n_outputs: int, output_amount: int, wallet: WalletPolicy) -> Tuple[CTransaction, int, int, int]:
    """
    Creates a (fake) transaction that has n_inputs inputs and n_outputs outputs, with a random output equal to output_amount.
    Each output of the transaction is a spend to wallet (possibly to a change address); the change/address_index of the
    derivation of the selected output are also returned.
    """
    assert n_inputs > 0 and n_outputs > 0

    selected_output_index = randint(0, n_outputs - 1)
    selected_output_change = randint(0, 1)
    selected_output_address_index = randint(0, 10_000)

    vout: List[CTxOut] = []
    for i in range(n_outputs):
        if i == selected_output_index:
            scriptPubKey: bytes = getScriptPubkeyFromWallet(
                wallet, selected_output_change, selected_output_address_index).data
            vout.append(CTxOut(output_amount, scriptPubKey))
        else:
            # could use any other script for the other outputs; doesn't really matter
            scriptPubKey: bytes = getScriptPubkeyFromWallet(
                wallet, randint(0, 1), randint(0, 10_000)).data
            vout.append(CTxOut(randint(0, 100_000_000), scriptPubKey))

    vin: List[CTxIn] = []
    for _ in range(n_inputs):
        txIn = CTxIn()
        txIn.prevout = COutPoint(
            uint256_from_str(random_txid()), randint(0, 20))
        txIn.nSequence = 0
        txIn.scriptSig = random_bytes(80)  # dummy
        vin.append(txIn)

    tx = CTransaction()
    tx.vin = vin
    tx.vout = vout
    tx.nVersion = 2
    tx.nLockTime = 0

    tx.wit = CTxWitness()

    # if segwit, add witness_utxo
    if Script(getScriptPubkeyFromWallet(wallet, 0, 0)).script_type in ["p2wpkh", "p2wsh", "p2tr"]:
        for _ in range(n_inputs):
            script_wit = CScriptWitness()
            script_wit.stack = [random_bytes(64)]  # dummy
            in_wit = CTxInWitness()
            in_wit.scriptWitness = script_wit
            tx.wit.vtxinwit.append(in_wit)

    tx.rehash()

    return tx, selected_output_index, selected_output_change, selected_output_address_index


def get_placeholder_root_key(placeholder: KeyPlaceholder, keys_info: List[str]) -> Tuple[ExtendedKey, Optional[KeyOriginInfo]]:
    if isinstance(placeholder, PlainKeyPlaceholder):
        key_info = keys_info[placeholder.key_index]
        key_origin_end_pos = key_info.find("]")
        if key_origin_end_pos == -1:
            xpub = key_info
            root_key_origin = None
        else:
            xpub = key_info[key_origin_end_pos+1:]
            root_key_origin = KeyOriginInfo.from_string(
                key_info[1:key_origin_end_pos])
        root_pubkey = ExtendedKey.deserialize(xpub)
    else:
        raise ValueError("Unsupported placeholder type")

    return root_pubkey, root_key_origin


def fill_inout(wallet_policy: WalletPolicy, inout: Union[PartiallySignedInput, PartiallySignedOutput], is_change: bool, address_index: int):
    desc_tmpl = DescriptorTemplate.from_string(
        wallet_policy.descriptor_template)

    if isinstance(desc_tmpl, TrDescriptorTemplate):
        keypath_der_subpath = [
            desc_tmpl.key.num1 if not is_change else desc_tmpl.key.num2,
            address_index
        ]

        keypath_pubkey, _ = get_placeholder_root_key(
            desc_tmpl.key, wallet_policy.keys_info)

        inout.tap_internal_key = keypath_pubkey.derive_pub_path(
            keypath_der_subpath).pubkey[1:]

        if desc_tmpl.tree is not None:
            inout.tap_merkle_root = desc_tmpl.get_taptree_hash(
                wallet_policy.keys_info, is_change, address_index)

        for placeholder, tapleaf_desc in desc_tmpl.placeholders():
            root_pubkey, root_pubkey_origin = get_placeholder_root_key(
                placeholder, wallet_policy.keys_info)

            placeholder_der_subpath = [
                placeholder.num1 if not is_change else placeholder.num2,
                address_index
            ]

            leaf_script = None
            if tapleaf_desc is not None:
                leaf_desc = derive_plain_descriptor(
                    tapleaf_desc, wallet_policy.keys_info, is_change, address_index)
                s = BytesIO(leaf_desc.encode())
                desc: Miniscript = Miniscript.read_from(s, taproot=True)
                leaf_script = desc.compile()

            derived_pubkey = root_pubkey.derive_pub_path(
                placeholder_der_subpath)

            if root_pubkey_origin is not None:
                derived_key_origin = KeyOriginInfo(
                    root_pubkey_origin.fingerprint, root_pubkey_origin.path + placeholder_der_subpath)

                leaf_hashes = []
                if leaf_script is not None:
                    # In BIP-388 compliant wallet policies, there will be only one tapleaf with a given key
                    leaf_hashes = [tapleaf_hash(leaf_script)]

                inout.tap_bip32_paths[derived_pubkey.pubkey[1:]] = (
                    leaf_hashes, derived_key_origin)
    else:
        if isinstance(desc_tmpl, WshDescriptorTemplate):
            # add witnessScript
            desc_str = derive_plain_descriptor(
                wallet_policy.descriptor_template, wallet_policy.keys_info, is_change, address_index)
            s = BytesIO(desc_str.encode())
            desc: Descriptor = Descriptor.read_from(s)
            inout.witness_script = desc.witness_script().data

        for placeholder, _ in desc_tmpl.placeholders():
            root_pubkey, root_pubkey_origin = get_placeholder_root_key(
                placeholder, wallet_policy.keys_info)

            placeholder_der_subpath = [
                placeholder.num1 if not is_change else placeholder.num2,
                address_index
            ]

            derived_pubkey = root_pubkey.derive_pub_path(
                placeholder_der_subpath)

            if root_pubkey_origin is not None:
                derived_key_origin = KeyOriginInfo(
                    root_pubkey_origin.fingerprint, root_pubkey_origin.path + placeholder_der_subpath)

                inout.hd_keypaths[derived_pubkey.pubkey] = derived_key_origin


def createPsbt(wallet_policy: WalletPolicy, input_amounts: List[int], output_amounts: List[int], output_is_change: List[bool]) -> PSBT:
    assert len(output_amounts) == len(output_is_change)
    assert sum(output_amounts) <= sum(input_amounts)

    vin: List[CTxIn] = [CTxIn() for _ in input_amounts]
    vout: List[CTxOut] = [CTxOut() for _ in output_amounts]

    # create some credible prevout transactions
    prevouts: List[CTransaction] = []
    prevout_ns: List[int] = []
    prevout_path_change: List[int] = []
    prevout_path_addr_idx: List[int] = []
    for i, prevout_amount in enumerate(input_amounts):
        n_inputs = randint(1, 10)
        n_outputs = randint(1, 10)
        prevout, idx, is_change, addr_idx = createFakeWalletTransaction(
            n_inputs, n_outputs, prevout_amount, wallet_policy)
        prevouts.append(prevout)
        prevout_ns.append(idx)
        prevout_path_change.append(is_change)
        prevout_path_addr_idx.append(addr_idx)

        vin[i].prevout = COutPoint(prevout.sha256, idx)
        vin[i].scriptSig = b''
        vin[i].nSequence = 0

    psbt = PSBT()
    psbt.version = 0

    tx = CTransaction()
    tx.vin = vin
    tx.vout = vout
    tx.wit = CTxWitness()

    change_address_index = randint(0, 10_000)
    for i, output_amount in enumerate(output_amounts):
        tx.vout[i].nValue = output_amount
        if output_is_change[i]:
            script = getScriptPubkeyFromWallet(
                wallet_policy, output_is_change[i], change_address_index)

            tx.vout[i].scriptPubKey = script.data
        else:
            # a random P2TR output
            tx.vout[i].scriptPubKey = random_p2tr()

    psbt.inputs = [PartiallySignedInput(0) for _ in input_amounts]
    psbt.outputs = [PartiallySignedOutput(0) for _ in output_amounts]

    desc_tmpl = DescriptorTemplate.from_string(
        wallet_policy.descriptor_template)

    for input_index, input in enumerate(psbt.inputs):
        if desc_tmpl.is_segwit():
            # add witness UTXO
            input.witness_utxo = prevouts[input_index].vout[prevout_ns[input_index]]

        if desc_tmpl.is_legacy() or (desc_tmpl.is_segwit() and not desc_tmpl.is_taproot()):
            # add non_witness_utxo for legacy or segwitv0
            input.non_witness_utxo = prevouts[input_index]

        is_change = bool(prevout_path_change[input_index])
        address_index = prevout_path_addr_idx[input_index]

        fill_inout(wallet_policy, input, is_change, address_index)

    # only for the change output, we need to do the same
    for output_index, output in enumerate(psbt.outputs):
        if output_is_change[output_index]:
            fill_inout(wallet_policy, output, is_change=True,
                       address_index=change_address_index)

    psbt.tx = tx

    return psbt
