#pragma once

#include "../common/bip32.h"
#include "../boilerplate/dispatcher.h"

typedef struct {
    machine_context_t ctx;

    uint8_t bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint64_t message_length;
    uint8_t message_merkle_root[32];

    cx_sha256_t msg_hash_context;    // used to compute sha256(message)
    cx_sha256_t bsm_digest_context;  // used to compute the Bitcoin Message Signing digest

    uint8_t message_hash[32];
    uint8_t bsm_digest[32];
} sign_message_state_t;

void handler_sign_message(dispatcher_context_t *dispatcher_context, uint8_t p2);
