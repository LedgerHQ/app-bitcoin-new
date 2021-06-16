#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"

#include "lib/check_merkle_tree_sorted.h"
#include "lib/stream_merkle_leaf_element.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/stream_merkleized_map_value.h"
#include "flows/psbt_parse_rawtx.h"
#include "flows/psbt_process_redeemScript.h"

#define MAX_N_INPUTS_CAN_SIGN 16
#define MAX_N_OUTPUTS_CAN_SIGN 16

typedef struct {
    merkleized_map_commitment_t map;

    bool has_witnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    uint8_t prevout_hash[32];    // the prevout_hash of the current input
    int prevout_n;               // the prevout index of the current input
    int prevout_nSequence;       // the nSequence of the current input
    uint64_t prevout_amount;     // the value of the prevout of the current input

    uint8_t prevout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int prevout_scriptpubkey_len;

    uint32_t sighash_type;
} cur_input_info_t;

typedef struct {
    machine_context_t ctx;

    merkleized_map_commitment_t global_map; // 48 bytes

    int n_inputs;
    uint8_t inputs_root[20];  // merkle root of the vector of input maps commitments
    int n_outputs;
    uint8_t outputs_root[20]; // merkle root of the vector of output maps commitments

    bool signing_with_wallet;
    uint8_t wallet_id[32];

    uint32_t master_key_fingerprint;

    int cur_input_index;
    cur_input_info_t cur_input;

    cx_sha256_t hash_context;

    int nLocktime;                   // the nLocktime of the transaction

    uint64_t outputs_total_value;
    uint64_t inputs_total_value;

    

    uint8_t tmp[1+33];  // temporary array to store keys requested in the PSBT maps (at most a pubkey, for now)

    union {
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
