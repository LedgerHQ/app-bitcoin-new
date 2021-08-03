#pragma once

#include "../boilerplate/dispatcher.h"
#include "../common/merkle.h"


#define MAX_N_INPUTS_CAN_SIGN 32

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
    uint8_t inputs_root[32];  // merkle root of the vector of input maps commitments
    int n_outputs;
    uint8_t outputs_root[32]; // merkle root of the vector of output maps commitments

    bool is_wallet_canonical;
    int address_type;         // only relevant for canonical wallets
    int bip44_purpose;        // only relevant for canonical wallets

    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;
    union {
        uint8_t wallet_policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t wallet_policy_map;
    };

    uint32_t master_key_fingerprint;

    uint8_t internal_inputs[MAX_N_INPUTS_CAN_SIGN]; // TODO: use a bitvector

    bool has_external_inputs;

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

    uint8_t sighash[32];

    uint64_t inputs_total_value;
    uint64_t outputs_total_value;

    uint64_t internal_inputs_total_value;

    uint64_t change_outputs_total_value;

    int external_outputs_count; // count of external outputs that are shown to the user
    int change_count;           // count of outputs compatible with change outputs

    int our_key_derivation_length;
    uint32_t our_key_derivation[MAX_BIP32_PATH_STEPS];
} sign_psbt_state_t;


void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
