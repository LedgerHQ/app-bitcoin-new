#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"

#include "flows/check_merkle_tree_sorted.h"
#include "flows/stream_merkle_leaf_element.h"
#include "flows/get_merkleized_map.h"
#include "flows/get_merkleized_map_value.h"
#include "flows/stream_merkleized_map_value.h"
#include "flows/psbt_parse_rawtx.h"
#include "flows/psbt_process_redeemScript.h"

typedef struct {
    machine_context_t ctx;

    merkleized_map_commitment_t global_map; // 48 bytes

    int n_inputs;
    uint8_t inputs_root[20];
    int n_outputs;
    uint8_t outputs_root[20];

    uint32_t master_key_fingerprint;

    int cur_input_index;
    merkleized_map_commitment_t cur_input_map;
    uint8_t cur_prevout_hash[32];    // stores the prevout_hash of the current input
    int cur_prevout_n;               // stores the prevout index of the current input
    uint64_t cur_prevout_amount;     // stores the value of the prevout of the current input
    bool cur_input_has_witnessUtxo;
    bool cur_input_has_redeemScript;
    bool cur_input_has_sighash_type;


    uint8_t cur_input_prevout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int cur_input_prevout_scriptpubkey_len;

    cx_sha256_t hash_context;

    union {
        uint8_t cur_input_sighash_type_le[4]; // little-endian sighash type for the current input
        uint32_t cur_input_sighash_type;
    };

    uint8_t tmp[1+33];  // temporary array to store keys requested in the PSBT maps (at most a pubkey, for now)

    union {
        check_merkle_tree_sorted_state_t check_merkle_tree_sorted;
        stream_merkle_leaf_element_state_t stream_merkle_leaf_element;
        get_merkleized_map_state_t get_merkleized_map;
        get_merkleized_map_value_state_t get_merkleized_map_value;
        stream_merkleized_map_value_state_t stream_merkleized_map_value;
        psbt_parse_rawtx_state_t psbt_parse_rawtx;
        psbt_process_redeemScript_state_t psbt_process_redeemScript;
    } subcontext;
} sign_psbt_state_t;


void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
