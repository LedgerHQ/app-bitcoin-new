#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"

#define MAX_N_INPUTS_CAN_SIGN  64
#define MAX_N_OUTPUTS_CAN_SIGN 256

typedef struct {
    merkleized_map_commitment_t map;

    bool has_witnessUtxo;
    bool has_nonWitnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    bool has_bip32_derivation;
    uint8_t bip32_derivation_pubkey[33];  // the pubkey of the first PSBT_IN_BIP32_DERIVATION or
                                          // PSBT_IN_TAP_BIP32_DERIVATION key seen.
                                          // Could be 33 (legacy or segwitv0) or 32 bytes long
                                          // (taproot), based on the script type.

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_IN_BIP32_DERIVATION or PSBT_IN_TAP_BIP32_DERIVATION is
                                   // not the correct length.

    uint64_t prevout_amount;  // the value of the prevout of the current input

    uint8_t prevout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int prevout_scriptpubkey_len;

    // the script used when signing, either from the witness utxo or the redeem script
    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int script_len;

    uint32_t sighash_type;

    int change;
    int address_index;
} cur_input_info_t;

typedef struct {
    merkleized_map_commitment_t map;

    bool has_bip32_derivation;
    uint8_t bip32_derivation_pubkey[33];  // the pubkey of the first PSBT_OUT_BIP32_DERIVATION or
                                          // PSBT_OUT_TAP_BIP32_DERIVATION key seen.
                                          // Could be 33 (legacy or segwitv0) or 32 bytes long
                                          // (taproot), based on the script type.

    bool unexpected_pubkey_error;  // Set to true if the pubkey in the keydata of
                                   // PSBT_OUT_BIP32_DERIVATION or PSBT_OUT_TAP_BIP32_DERIVATION is
                                   // not the correct length.

    uint64_t value;
    uint8_t scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int scriptpubkey_len;

} cur_output_info_t;

typedef struct {
    machine_context_t ctx;

    merkleized_map_commitment_t global_map;  // 48 bytes

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

    uint8_t internal_inputs[MAX_N_INPUTS_CAN_SIGN];  // TODO: use a bitvector

    union {
        struct {
            unsigned int cur_input_index;
            cur_input_info_t cur_input;
        };
        struct {
            unsigned int cur_output_index;
            cur_output_info_t cur_output;
        };
    };

    uint8_t sighash[32];

    struct {
        uint8_t sha_prevouts[32];
        uint8_t sha_amounts[32];
        uint8_t sha_scriptpubkeys[32];
        uint8_t sha_sequences[32];
        uint8_t sha_outputs[32];
    } hashes;

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
