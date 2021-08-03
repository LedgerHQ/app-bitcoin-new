#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../common/wallet.h"
#include "../boilerplate/dispatcher.h"

#include "lib/get_merkle_leaf_element.h"

typedef struct {
    machine_context_t ctx;

    uint32_t address_index;
    uint8_t is_change;
    uint8_t display_address;

    bool is_wallet_canonical;
    int address_type;

    uint8_t wallet_header_keys_info_merkle_root[32];
    size_t wallet_header_n_keys;
    union {
        uint8_t wallet_policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t wallet_policy_map;
    };

    int address_len;
    char address[MAX_ADDRESS_LENGTH_STR + 1]; // null-terminated string
} get_wallet_address_state_t;


void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
