#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../common/wallet.h"
#include "../boilerplate/dispatcher.h"

#include "lib/get_merkle_leaf_element.h"

typedef struct {
    machine_context_t ctx;

    uint32_t address_index;
    multisig_wallet_header_t wallet_header;

    uint8_t display_address;

    // As this flow is complex, we reuse the same space in memory for different purposes
    union {
        struct {
            uint8_t next_pubkey_index;
            uint8_t next_pubkey_info[MAX_MULTISIG_SIGNER_INFO_LEN];

            // the index of the pubkeys, ranked in the correct order for the script
            // This is necessary to handle sortedmulti() correctly
            uint8_t ordered_pubkeys[15];

            // previous compressed pubkey, to validate lexicographic sorting in multisig
            uint8_t prev_compressed_pubkey[33];
        } stage0;
        struct {
            char address[MAX_ADDRESS_LENGTH_STR + 1];
            size_t address_len;
        } stage1;
    } shared;

    cx_sha256_t script_hash_context; // 108 bytes
} get_wallet_address_state_t;


void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
