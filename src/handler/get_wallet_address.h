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

    policy_map_wallet_header_t wallet_header;

    uint8_t wallet_id[32];
    union {
        uint8_t policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t policy_map;
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
