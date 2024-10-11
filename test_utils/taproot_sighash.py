# Based on code from the bitcoin's functional test framework, extracted from:
# https://github.com/bitcoin/bitcoin/blob/58446e1d92c7da46da1fc48e1eb5eefe2e0748cb/test/functional/feature_taproot.py
#
# Copyright (c) 2015-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying


import struct
from test_utils import sha256
from test_utils.taproot import ser_string, tagged_hash


def BIP341_sha_prevouts(txTo):
    return sha256(b"".join(i.prevout.serialize() for i in txTo.vin))


def BIP341_sha_amounts(spent_utxos):
    return sha256(b"".join(struct.pack("<q", u.nValue) for u in spent_utxos))


def BIP341_sha_scriptpubkeys(spent_utxos):
    return sha256(b"".join(ser_string(u.scriptPubKey) for u in spent_utxos))


def BIP341_sha_sequences(txTo):
    return sha256(b"".join(struct.pack("<I", i.nSequence) for i in txTo.vin))


def BIP341_sha_outputs(txTo):
    return sha256(b"".join(o.serialize() for o in txTo.vout))


LEAF_VERSION_TAPSCRIPT = 0xc0
SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80


def TaprootSignatureMsg(txTo, spent_utxos, hash_type, input_index=0, scriptpath=False, script=b'', codeseparator_pos=-1, annex=None, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    assert (len(txTo.vin) == len(spent_utxos))
    assert (input_index < len(txTo.vin))
    out_type = SIGHASH_ALL if hash_type == 0 else hash_type & 3
    in_type = hash_type & SIGHASH_ANYONECANPAY
    spk = spent_utxos[input_index].scriptPubKey
    ss = bytes([0, hash_type])  # epoch, hash_type
    ss += struct.pack("<i", txTo.nVersion)
    ss += struct.pack("<I", txTo.nLockTime)
    if in_type != SIGHASH_ANYONECANPAY:
        ss += BIP341_sha_prevouts(txTo)
        ss += BIP341_sha_amounts(spent_utxos)
        ss += BIP341_sha_scriptpubkeys(spent_utxos)
        ss += BIP341_sha_sequences(txTo)
    if out_type == SIGHASH_ALL:
        ss += BIP341_sha_outputs(txTo)
    spend_type = 0
    if annex is not None:
        spend_type |= 1
    if (scriptpath):
        spend_type |= 2
    ss += bytes([spend_type])
    if in_type == SIGHASH_ANYONECANPAY:
        ss += txTo.vin[input_index].prevout.serialize()
        ss += struct.pack("<q", spent_utxos[input_index].nValue)
        ss += ser_string(spk)
        ss += struct.pack("<I", txTo.vin[input_index].nSequence)
    else:
        ss += struct.pack("<I", input_index)
    if (spend_type & 1):
        ss += sha256(ser_string(annex))
    if out_type == SIGHASH_SINGLE:
        if input_index < len(txTo.vout):
            ss += sha256(txTo.vout[input_index].serialize())
        else:
            ss += bytes(0 for _ in range(32))
    if (scriptpath):
        ss += tagged_hash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        ss += bytes([0])
        ss += struct.pack("<i", codeseparator_pos)
    return ss


def TaprootSignatureHash(txTo, spent_utxos, hash_type, input_index=0, scriptpath=False, script=b'', codeseparator_pos=-1, annex=None, leaf_ver=LEAF_VERSION_TAPSCRIPT):
    return tagged_hash("TapSighash", TaprootSignatureMsg(txTo, spent_utxos, hash_type, input_index, scriptpath, script, codeseparator_pos, annex, leaf_ver))
