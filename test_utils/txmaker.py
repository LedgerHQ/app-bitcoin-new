from random import randint

from typing import List, Tuple
from bitcoin_client.ledger_bitcoin import PolicyMapWallet
from bitcoin_client.ledger_bitcoin.key import KeyOriginInfo, parse_path
from bitcoin_client.ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from bitcoin_client.ledger_bitcoin.tx import CScriptWitness, CTransaction, CTxIn, CTxInWitness, CTxOut, COutPoint, CTxWitness, uint256_from_str

from embit.descriptor import Descriptor
from embit.script import Script
from embit.bip32 import HDKey
from embit.bip39 import mnemonic_to_seed

SPECULOS_SEED = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
master_key = HDKey.from_seed(mnemonic_to_seed(SPECULOS_SEED))
master_key_fpr = master_key.derive("m/0'").fingerprint


def random_numbers_with_sum(n: int, s: int) -> List[int]:
    """Returns a list of n random numbers with sum s."""
    assert n > 1

    separators = list(sorted([randint(0, s) for _ in range(n - 1)]))
    return [
        separators[0],
        *[separators[i + 1] - separators[i] for i in range(len(separators) - 1)],
        s - separators[-1]
    ]


def random_bytes(n: int) -> bytes:
    """Returns n random bytes. Not cryptographically secure."""
    return bytes([randint(0, 255) for _ in range(n)])


def random_txid() -> bytes:
    """Returns 32 random bytes. Not cryptographically secure."""
    return random_bytes(32)


def getScriptPubkeyFromWallet(wallet: PolicyMapWallet, change: bool, address_index: int) -> Script:
    descriptor_str = wallet.policy_map

    # Iterate in reverse order, as strings identifying a small-index key (like @1) can be a
    # prefix of substrings identifying a large-index key (like @12), but not the other way around
    # A more structural parsing would be more robust
    for i, key_info_str in enumerate(reversed(wallet.keys_info)):
        if key_info_str[-3:] != "/**":
            raise ValueError("All the keys must have wildcard (/**)")

        key_info_str = key_info_str[:-3] + f"/{1 if change else 0}/*"

        if f"@{i}" not in descriptor_str:
            raise ValueError(f"Invalid policy: not using key @{i}")

        descriptor_str = descriptor_str.replace(f"@{i}", key_info_str)

    return Descriptor.from_string(descriptor_str).derive(address_index).script_pubkey()


def createFakeWalletTransaction(n_inputs: int, n_outputs: int, output_amount: int, wallet: PolicyMapWallet) -> Tuple[CTransaction, int, int, int]:
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
            scriptPubKey: bytes = getScriptPubkeyFromWallet(wallet, randint(0, 1), randint(0, 10_000)).data
            vout.append(CTxOut(randint(0, 100_000_000), scriptPubKey))

    vin: List[CTxIn] = []
    for _ in range(n_inputs):
        txIn = CTxIn()
        txIn.prevout = COutPoint(uint256_from_str(random_txid()), randint(0, 20))
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


def createPsbt(wallet: PolicyMapWallet, input_amounts: List[int], output_amounts: List[int], output_is_change: List[bool]) -> PSBT:
    assert len(output_amounts) == len(output_is_change)
    assert sum(output_amounts) <= sum(input_amounts)

    # TODO: add support for wrapped segwit wallets

    if wallet.n_keys != 1:
        raise NotImplementedError("Only 1-key wallets supported")
    if wallet.policy_map not in ["pkh(@0)", "wpkh(@0)", "tr(@0)"]:
        raise NotImplementedError("Unsupported policy type")

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
        prevout, idx, is_change, addr_idx = createFakeWalletTransaction(n_inputs, n_outputs, prevout_amount, wallet)
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

    psbt.inputs = [PartiallySignedInput() for _ in input_amounts]
    psbt.outputs = [PartiallySignedOutput() for _ in output_amounts]

    # simplification; good enough for the scripts we support now, but will need more work
    is_legacy = "pkh("
    is_segwitv0 = wallet.policy_map.startswith("wpkh(") or wallet.policy_map.startswith("sh(wpkh(")
    is_taproot = wallet.policy_map.startswith("tr(")

    key_origin = wallet.keys_info[0][1:wallet.keys_info[0].index("]")]

    for i in range(len(input_amounts)):
        if is_legacy or is_segwitv0:
            # add non-witness UTXO
            psbt.inputs[i].non_witness_utxo = prevouts[i]
        if is_segwitv0 or is_taproot:
            # add witness UTXO
            psbt.inputs[i].witness_utxo = prevouts[i].vout[prevout_ns[i]]

        path_str = f"m{key_origin[8:]}/{prevout_path_change[i]}/{prevout_path_addr_idx[i]}"
        path = parse_path(path_str)
        input_key: bytes = master_key.derive(path_str).key.sec()

        assert len(input_key) == 33

        # add key and path info
        if is_legacy or is_segwitv0:
            psbt.inputs[i].hd_keypaths[input_key] = KeyOriginInfo(master_key_fpr, path)
        elif is_taproot:
            psbt.inputs[i].tap_hd_keypaths[input_key[1:]] = (list(), KeyOriginInfo(master_key_fpr, path))
        else:
            raise RuntimeError("Unexpected state: unknown transaction type")

    for i, output_amount in enumerate(output_amounts):
        # TODO: we could use a completely different script/wallet for non-change outputs
        # Since we don't add path information for non-change output, the wallet will consider them external,
        # so it works for now.

        script = getScriptPubkeyFromWallet(wallet, output_is_change[i], i)
        tx.vout[i].scriptPubKey = script.data
        tx.vout[i].nValue = output_amount

        if output_is_change[i]:
            path_str = f"m{key_origin[8:]}/1/{i}"
            path = parse_path(path_str)
            output_key: bytes = master_key.derive(path_str).key.sec()

            # add key and path information for change output
            if is_legacy or is_segwitv0:
                psbt.outputs[i].hd_keypaths[output_key] = KeyOriginInfo(master_key_fpr, path)
            elif is_taproot:
                psbt.outputs[i].tap_hd_keypaths[output_key[1:]] = (list(), KeyOriginInfo(master_key_fpr, path))

    psbt.tx = tx

    return psbt
