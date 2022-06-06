#pragma once

#include "../boilerplate/dispatcher.h"
#include "../constants.h"
#include "../common/bitvector.h"
#include "../common/merkle.h"
#include "../common/wallet.h"

#define MAX_N_INPUTS_CAN_SIGN 512

// common info that applies to either the current input or the current output
typedef struct {
    merkleized_map_commitment_t map;

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_{IN,OUT}_BIP32_DERIVATION or
                                   // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION is not the correct length.

    bool has_bip32_derivation;
    uint8_t
        bip32_derivation_pubkey[33];  // the pubkey of the first PSBT_{IN,OUT}_BIP32_DERIVATION or
                                      // PSBT_{IN,OUT}_TAP_BIP32_DERIVATION key seen.
                                      // Could be 33 (legacy or segwitv0) or 32 bytes long
                                      // (taproot), based on the script type.

    // For an output, its scriptPubKey
    // for an input, the prevout's scriptPubKey (either from the non-witness-utxo, or from the
    // witness-utxo)

    uint8_t scriptPubKey[MAX_OUTPUT_SCRIPTPUBKEY_LEN];
    size_t scriptPubKey_len;
} in_out_info_t;

typedef struct {
    bool has_witnessUtxo;
    bool has_nonWitnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    uint64_t prevout_amount;  // the value of the prevout of the current input

    uint8_t prevout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    size_t prevout_scriptpubkey_len;

    // the script used when signing, either from the witness utxo or the redeem script
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    size_t script_len;

    uint32_t sighash_type;

    int change;
    int address_index;
} input_info_t;

typedef struct {
    uint64_t value;
} output_info_t;

typedef struct {
    machine_context_t ctx;

    uint32_t tx_version;
    uint32_t locktime;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    bool is_wallet_canonical;
    int address_type;   // only relevant for canonical wallets
    int bip44_purpose;  // only relevant for canonical wallets

    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;
    union {
        uint8_t wallet_policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t wallet_policy_map;
    };

    uint32_t master_key_fingerprint;

    // bitmap to track of which inputs are internal
    uint8_t internal_inputs[BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)];

    union {
        unsigned int cur_input_index;
        unsigned int cur_output_index;
    };

    struct {
        in_out_info_t in_out;
        union {
            input_info_t input;
            output_info_t output;
        };
    } cur;

    // if any segwitv0 input is missing the non-witness-utxo, we show a warning
    bool show_missing_nonwitnessutxo_warning;

    uint8_t sighash[32];

    struct {
        uint8_t sha_prevouts[32];
        uint8_t sha_amounts[32];
        uint8_t sha_scriptpubkeys[32];
        uint8_t sha_sequences[32];
        uint8_t sha_outputs[32];
    } hashes;
    bool segwit_hashes_computed;

    uint64_t inputs_total_value;
    uint64_t outputs_total_value;

    uint64_t internal_inputs_total_value;

    uint64_t change_outputs_total_value;

    int external_outputs_count;  // count of external outputs that are shown to the user
    int change_count;            // count of outputs compatible with change outputs

    int our_key_derivation_length;
    uint32_t our_key_derivation[MAX_BIP32_PATH_STEPS];
} sign_psbt_state_t;

void handler_sign_psbt(dispatcher_context_t *dispatcher_context);
