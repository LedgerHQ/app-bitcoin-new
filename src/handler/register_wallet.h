#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

#include "wallet.h"


typedef struct {
    multisig_wallet_header_t wallet_header;

    uint8_t next_pubkey_index;

    cx_sha256_t hash_context;
} register_wallet_state_t;

void handler_register_wallet(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
