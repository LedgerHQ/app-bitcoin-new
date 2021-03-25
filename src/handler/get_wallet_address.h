#pragma once

#include "../crypto.h"
#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

#include "wallet.h"

typedef struct {
    uint32_t address_index;
    multisig_wallet_header_t wallet_header;

    uint8_t wallet_hash[32]; // wallet hash provided by the host
    cx_sha256_t wallet_hash_context;

    uint8_t next_pubkey_index;
    uint8_t p1, p2;

    // TODO: only 3 for now, not enough memory. (this MUST be fixed)
    uint8_t derived_cosigner_pubkeys[3][33]; // up to 15 compressed pubkeys, in the same order as the cosigners

    char address[MAX_ADDRESS_LENGTH_STR + 1];
    size_t address_len;
} get_wallet_address_state_t;

void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
);
