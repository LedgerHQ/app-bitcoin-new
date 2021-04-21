#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

#include "wallet.h"

#include "flows/get_merkle_leaf_element.h"

// TODO:
// - refactor flow using Merkle trees; delete CCMD_GET_PUBKEY_INFO;
// - think of a more general command to replace CCMD_GET_SORTED_PUBKEY_INFO, if possible
//
// Possible replacement for CCMD_GET_SORTED_PUBKEY_INFO:
// - give the Merkle key info tree, a subset of indexes of those keys, and a derivation path, the client returns
//   the list of indexes such that the corresponing derived pubkeys are in lexicographical order.
//   This might better generalize to future complex scripts where sortedmulti() descriptors involve only a subset of the keys.


typedef struct {
    machine_context_t ctx;

    uint32_t address_index;
    multisig_wallet_header_t wallet_header;

    uint8_t next_pubkey_index;
    uint8_t next_pubkey_info[MAX_MULTISIG_SIGNER_INFO_LEN];

    uint8_t display_address;

    char address[MAX_ADDRESS_LENGTH_STR + 1];
    size_t address_len;

    // the index of the pubkeys, ranked in the correct order for the script
    // This is necessary to handle sortedmulti() correctly
    uint8_t ordered_pubkeys[15];

    // previous compressed pubkey, to validate lexicographic sorting in multisig
    uint8_t prev_compressed_pubkey[33];
    cx_sha256_t script_hash_context;

    union {
        get_merkle_leaf_element_state_t get_merkle_leaf_element;
    } subcontext;
} get_wallet_address_state_t;


void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
