#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

#define WALLET_TYPE_MULTISIG 0


typedef struct {
    uint8_t threshold;
    uint8_t n_keys;
    uint8_t wallet_name[MAX_WALLET_NAME_LENGTH + 1];
    uint8_t next_pubkey_index;

    cx_sha256_t wallet_hash_context;
} register_wallet_state_t;

int handler_register_wallet(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
