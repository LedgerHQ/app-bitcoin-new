#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"

#include "lib/check_merkle_tree_sorted.h"
#include "lib/stream_merkle_leaf_element.h"
#include "lib/get_merkleized_map.h"
#include "lib/get_merkleized_map_value.h"
#include "lib/stream_merkleized_map_value.h"
#include "lib/psbt_process_redeemScript.h"
#include "flows/psbt_parse_rawtx.h"

#define MAX_N_INPUTS_CAN_SIGN 16
#define MAX_N_OUTPUTS_CAN_SIGN 16

typedef struct {
    merkleized_map_commitment_t map;

    bool has_witnessUtxo;
    bool has_redeemScript;
    bool has_sighash_type;

    bool has_bip32_derivation;
    uint8_t bip32_derivation_pubkey[33]; // the pubkey of the first PSBT_IN_BIP32_DERIVATION seen key
    bool unexpected_pubkey_error; // set to true if the pubkey in the keydata of PSBT_IN_BIP32_DERIVATION is not 33 bytes long

    uint64_t prevout_amount;     // the value of the prevout of the current input

    uint8_t prevout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int prevout_scriptpubkey_len;

    uint32_t sighash_type;

    int change;
    int address_index;
} cur_input_info_t;

typedef struct {
    merkleized_map_commitment_t map;

    bool has_bip32_derivation;
    uint8_t bip32_derivation_pubkey[33]; // the pubkey of the first PSBT_OUT_BIP32_DERIVATION seen key
    bool unexpected_pubkey_error; // set to true if the pubkey in the keydata of PSBT_IN_BIP32_DERIVATION is not 33 bytes long

    uint64_t value;
    uint8_t scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int scriptpubkey_len;

} cur_output_info_t;


typedef struct {
    machine_context_t ctx;

    merkleized_map_commitment_t global_map; // 48 bytes

    uint32_t tx_version;
    uint32_t locktime;

    int n_inputs;
    uint8_t inputs_root[20];  // merkle root of the vector of input maps commitments
    int n_outputs;
    uint8_t outputs_root[20]; // merkle root of the vector of output maps commitments

    policy_map_wallet_header_t wallet_header;
    union {
        uint8_t wallet_policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t wallet_policy_map;
    };

    uint32_t master_key_fingerprint;

    uint8_t internal_inputs[MAX_N_INPUTS_CAN_SIGN]; // TODO: use a bitvector

    union {
        struct {
            int cur_input_index;
            cur_input_info_t cur_input;
        };
        struct {
            int cur_output_index;
            cur_output_info_t cur_output;
        };
    };

    cx_sha256_t hash_context;

    int nLocktime;                   // the nLocktime of the transaction

    uint64_t inputs_total_value;
    uint64_t outputs_total_value;

    uint64_t internal_inputs_total_value;
    uint64_t internal_outputs_total_value;
    

    uint8_t tmp[1];  // temporary array for calls that need a param allocated in the state (call_psbt_parse_rawtx)

    policy_map_key_info_t our_key_info;

    union {
        psbt_parse_rawtx_state_t psbt_parse_rawtx;
    } subcontext;
} sign_psbt_state_t;


void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
