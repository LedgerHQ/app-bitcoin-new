#pragma once

#include "../boilerplate/dispatcher.h"
#include "../constants.h"
#include "../common/merkle.h"
#include "../common/wallet.h"
#include "../crypto.h"

#define MAX_N_INPUTS_CAN_SIGN 512

typedef struct {
    uint32_t master_key_fingerprint;
    uint32_t tx_version;
    uint32_t locktime;

    unsigned int n_inputs;
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    unsigned int n_outputs;
    uint8_t outputs_root[32];  // merkle root of the vector of output maps commitments

    uint64_t inputs_total_value;
    uint64_t outputs_total_value;

    uint64_t internal_inputs_total_value;

    uint64_t change_outputs_total_value;

    bool is_wallet_canonical;

    uint8_t p2;

    union {
        uint8_t wallet_policy_map_bytes[MAX_WALLET_POLICY_BYTES];
        policy_node_t wallet_policy_map;
    };

    int wallet_header_version;
    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;

    // if any segwitv0 input is missing the non-witness-utxo, we show a warning
    bool show_missing_nonwitnessutxo_warning;

    // if any of the internal inputs has non-default sighash, we show a warning
    bool show_nondefault_sighash_warning;

    int external_outputs_count;  // count of external outputs that are shown to the user
    int change_count;            // count of outputs compatible with change outputs

    // Cache for partial hashes (avoid quadratic hashing for segwit transactions)
    struct {
        uint8_t sha_prevouts[32];
        uint8_t sha_amounts[32];
        uint8_t sha_scriptpubkeys[32];
        uint8_t sha_sequences[32];
        uint8_t sha_outputs[32];
    } hashes;
    bool segwit_hashes_computed;
} sign_psbt_state_t;

void handler_sign_psbt(dispatcher_context_t *dispatcher_context, uint8_t p2);
