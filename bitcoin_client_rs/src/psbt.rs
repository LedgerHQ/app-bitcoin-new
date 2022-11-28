/// code is from github.com/rust-bitcoin/rust-bitcoin
/// SPDX-License-Identifier: CC0-1.0
///
/// Note: Only psbt V2 is supported by the ledger bitcoin app.
/// rust-bitcoin currently support V0.
use bitcoin::{
    blockdata::transaction::{TxIn, TxOut},
    consensus::encode::{deserialize, serialize, VarInt},
    util::psbt::{raw, Input, Output, Psbt},
};

#[rustfmt::skip]
macro_rules! impl_psbt_get_pair {
    ($rv:ident.push($slf:ident.$unkeyed_name:ident, $unkeyed_typeval:ident)) => {
        if let Some(ref $unkeyed_name) = $slf.$unkeyed_name {
            $rv.push(bitcoin::util::psbt::raw::Pair {
                key: bitcoin::util::psbt::raw::Key {
                    type_value: $unkeyed_typeval,
                    key: vec![],
                },
                value: bitcoin::util::psbt::serialize::Serialize::serialize($unkeyed_name),
            });
        }
    };
    ($rv:ident.push_map($slf:ident.$keyed_name:ident, $keyed_typeval:ident)) => {
        for (key, val) in &$slf.$keyed_name {
            $rv.push(bitcoin::util::psbt::raw::Pair {
                key: bitcoin::util::psbt::raw::Key {
                    type_value: $keyed_typeval,
                    key: bitcoin::util::psbt::serialize::Serialize::serialize(key),
                },
                value: bitcoin::util::psbt::serialize::Serialize::serialize(val),
            });
        }
    };
}

/// V0, Type: Unsigned Transaction PSBT_GLOBAL_UNSIGNED_TX = 0x00
/// const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
/// Type: Extended Public Key PSBT_GLOBAL_XPUB = 0x01
const PSBT_GLOBAL_XPUB: u8 = 0x01;
/// V2 field
const PSBT_GLOBAL_TX_VERSION: u8 = 0x02;
/// V2 field
const PSBT_GLOBAL_FALLBACK_LOCKTIME: u8 = 0x03;
/// V2 field
const PSBT_GLOBAL_INPUT_COUNT: u8 = 0x04;
/// V2 field
const PSBT_GLOBAL_OUTPUT_COUNT: u8 = 0x05;
/// V2 field
/// const PSBT_GLOBAL_TX_MODIFIABLE: u8 = 0x06;
/// Type: Version Number PSBT_GLOBAL_VERSION = 0xFB
const PSBT_GLOBAL_VERSION: u8 = 0xFB;

pub fn get_v2_global_pairs(psbt: &Psbt) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    for (xpub, (fingerprint, derivation)) in &psbt.xpub {
        rv.push(raw::Pair {
            key: raw::Key {
                type_value: PSBT_GLOBAL_XPUB,
                key: xpub.encode().to_vec(),
            },
            value: {
                let mut ret = Vec::with_capacity(4 + derivation.len() * 4);
                ret.extend(fingerprint.as_bytes());
                derivation
                    .into_iter()
                    .for_each(|n| ret.extend(&u32::from(*n).to_le_bytes()));
                ret
            },
        });
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_FALLBACK_LOCKTIME,
            key: vec![],
        },
        value: serialize(&psbt.unsigned_tx.lock_time),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_INPUT_COUNT,
            key: vec![],
        },
        value: serialize(&VarInt(psbt.inputs.len() as u64)),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_OUTPUT_COUNT,
            key: vec![],
        },
        value: serialize(&VarInt(psbt.outputs.len() as u64)),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_TX_VERSION,
            key: vec![],
        },
        value: (psbt.unsigned_tx.version as u32).to_le_bytes().to_vec(),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_GLOBAL_VERSION,
            key: vec![],
        },
        value: 2_u32.to_le_bytes().to_vec(),
    });

    for (key, value) in psbt.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in psbt.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

/// Type: Non-Witness UTXO PSBT_IN_NON_WITNESS_UTXO = 0x00
const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
/// Type: Witness UTXO PSBT_IN_WITNESS_UTXO = 0x01
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
/// Type: Partial Signature PSBT_IN_PARTIAL_SIG = 0x02
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
/// Type: Sighash Type PSBT_IN_SIGHASH_TYPE = 0x03
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
/// Type: Redeem Script PSBT_IN_REDEEM_SCRIPT = 0x04
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
/// Type: Witness Script PSBT_IN_WITNESS_SCRIPT = 0x05
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
/// Type: BIP 32 Derivation Path PSBT_IN_BIP32_DERIVATION = 0x06
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
/// Type: Finalized scriptSig PSBT_IN_FINAL_SCRIPTSIG = 0x07
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
/// Type: Finalized scriptWitness PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
/// V2
const PSBT_IN_PREVIOUS_TXID: u8 = 0x0e;
/// V2
const PSBT_IN_SEQUENCE: u8 = 0x10;
/// V2
/// const PSBT_IN_REQUIRED_TIME_LOCKTIME: u8 = 0x11;
/// V2
///const PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: u8 = 0x12;
const PSBT_IN_OUTPUT_INDEX: u8 = 0x0f;
/// Type: RIPEMD160 preimage PSBT_IN_RIPEMD160 = 0x0a
const PSBT_IN_RIPEMD160: u8 = 0x0a;
/// Type: SHA256 preimage PSBT_IN_SHA256 = 0x0b
const PSBT_IN_SHA256: u8 = 0x0b;
/// Type: HASH160 preimage PSBT_IN_HASH160 = 0x0c
const PSBT_IN_HASH160: u8 = 0x0c;
/// Type: HASH256 preimage PSBT_IN_HASH256 = 0x0d
const PSBT_IN_HASH256: u8 = 0x0d;
/// Type: Schnorr Signature in Key Spend PSBT_IN_TAP_KEY_SIG = 0x13
const PSBT_IN_TAP_KEY_SIG: u8 = 0x13;
/// Type: Schnorr Signature in Script Spend PSBT_IN_TAP_SCRIPT_SIG = 0x14
const PSBT_IN_TAP_SCRIPT_SIG: u8 = 0x14;
/// Type: Taproot Leaf Script PSBT_IN_TAP_LEAF_SCRIPT = 0x14
const PSBT_IN_TAP_LEAF_SCRIPT: u8 = 0x15;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_IN_TAP_BIP32_DERIVATION = 0x16
const PSBT_IN_TAP_BIP32_DERIVATION: u8 = 0x16;
/// Type: Taproot Internal Key PSBT_IN_TAP_INTERNAL_KEY = 0x17
const PSBT_IN_TAP_INTERNAL_KEY: u8 = 0x17;
/// Type: Taproot Merkle Root PSBT_IN_TAP_MERKLE_ROOT = 0x18
const PSBT_IN_TAP_MERKLE_ROOT: u8 = 0x18;

pub fn get_v2_input_pairs(input: &Input, txin: &TxIn) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    impl_psbt_get_pair! {
        rv.push(input.non_witness_utxo, PSBT_IN_NON_WITNESS_UTXO)
    }

    impl_psbt_get_pair! {
        rv.push(input.witness_utxo, PSBT_IN_WITNESS_UTXO)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.partial_sigs, PSBT_IN_PARTIAL_SIG)
    }

    impl_psbt_get_pair! {
        rv.push(input.sighash_type, PSBT_IN_SIGHASH_TYPE)
    }

    impl_psbt_get_pair! {
        rv.push(input.redeem_script, PSBT_IN_REDEEM_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push(input.witness_script, PSBT_IN_WITNESS_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.bip32_derivation, PSBT_IN_BIP32_DERIVATION)
    }

    impl_psbt_get_pair! {
        rv.push(input.final_script_sig, PSBT_IN_FINAL_SCRIPTSIG)
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_PREVIOUS_TXID,
            key: vec![],
        },
        value: serialize(&txin.previous_output.txid),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_OUTPUT_INDEX,
            key: vec![],
        },
        value: serialize(&txin.previous_output.vout),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_IN_SEQUENCE,
            key: vec![],
        },
        value: serialize(&txin.sequence),
    });

    impl_psbt_get_pair! {
        rv.push(input.final_script_witness, PSBT_IN_FINAL_SCRIPTWITNESS)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.ripemd160_preimages, PSBT_IN_RIPEMD160)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.sha256_preimages, PSBT_IN_SHA256)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.hash160_preimages, PSBT_IN_HASH160)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.hash256_preimages, PSBT_IN_HASH256)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_key_sig, PSBT_IN_TAP_KEY_SIG)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_script_sigs, PSBT_IN_TAP_SCRIPT_SIG)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_scripts, PSBT_IN_TAP_LEAF_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(input.tap_key_origins, PSBT_IN_TAP_BIP32_DERIVATION)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_internal_key, PSBT_IN_TAP_INTERNAL_KEY)
    }

    impl_psbt_get_pair! {
        rv.push(input.tap_merkle_root, PSBT_IN_TAP_MERKLE_ROOT)
    }

    for (key, value) in input.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in input.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

/// Type: Redeem Script PSBT_OUT_REDEEM_SCRIPT = 0x00
const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
/// Type: Witness Script PSBT_OUT_WITNESS_SCRIPT = 0x01
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
/// Type: BIP 32 Derivation Path PSBT_OUT_BIP32_DERIVATION = 0x02
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
/// V2
const PSBT_OUT_AMOUNT: u8 = 0x03;
/// V2
const PSBT_OUT_SCRIPT: u8 = 0x04;
/// Type: Taproot Internal Key PSBT_OUT_TAP_INTERNAL_KEY = 0x05
const PSBT_OUT_TAP_INTERNAL_KEY: u8 = 0x05;
/// Type: Taproot Tree PSBT_OUT_TAP_TREE = 0x06
const PSBT_OUT_TAP_TREE: u8 = 0x06;
/// Type: Taproot Key BIP 32 Derivation Path PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
const PSBT_OUT_TAP_BIP32_DERIVATION: u8 = 0x07;

pub fn get_v2_output_pairs(output: &Output, txout: &TxOut) -> Vec<raw::Pair> {
    let mut rv: Vec<raw::Pair> = Default::default();

    impl_psbt_get_pair! {
        rv.push(output.redeem_script, PSBT_OUT_REDEEM_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push(output.witness_script, PSBT_OUT_WITNESS_SCRIPT)
    }

    impl_psbt_get_pair! {
        rv.push_map(output.bip32_derivation, PSBT_OUT_BIP32_DERIVATION)
    }

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_OUT_AMOUNT,
            key: vec![],
        },
        value: txout.value.to_le_bytes().to_vec(),
    });

    rv.push(raw::Pair {
        key: raw::Key {
            type_value: PSBT_OUT_SCRIPT,
            key: vec![],
        },
        value: txout.script_pubkey.as_bytes().to_vec(),
    });

    impl_psbt_get_pair! {
        rv.push(output.tap_internal_key, PSBT_OUT_TAP_INTERNAL_KEY)
    }

    impl_psbt_get_pair! {
        rv.push(output.tap_tree, PSBT_OUT_TAP_TREE)
    }

    impl_psbt_get_pair! {
        rv.push_map(output.tap_key_origins, PSBT_OUT_TAP_BIP32_DERIVATION)
    }

    for (key, value) in output.proprietary.iter() {
        rv.push(raw::Pair {
            key: key.to_key(),
            value: value.clone(),
        });
    }

    for (key, value) in output.unknown.iter() {
        rv.push(raw::Pair {
            key: key.clone(),
            value: value.clone(),
        });
    }

    rv
}

pub fn deserialize_pairs(pair: raw::Pair) -> (Vec<u8>, Vec<u8>) {
    (deserialize(&serialize(&pair.key)).unwrap(), pair.value)
}
