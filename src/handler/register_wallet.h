#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../common/wallet.h"
#include "../boilerplate/dispatcher.h"

#include "lib/get_merkle_leaf_element.h"

typedef struct {
    machine_context_t ctx;

    policy_map_wallet_header_t wallet_header;

    uint8_t wallet_id[32];
    union {
        uint8_t policy_map_bytes[MAX_POLICY_MAP_BYTES];
        policy_node_t policy_map;
    };
    size_t n_internal_keys;

    uint32_t master_key_fingerprint;

    uint8_t next_pubkey_index;
    uint8_t next_pubkey_info[MAX_POLICY_KEY_INFO_LEN + 1];
} register_wallet_state_t;

void handler_register_wallet(dispatcher_context_t *dispatcher_context, uint8_t p2);
