#pragma once

#include <stdint.h>

#include "common/buffer.h"
#include "../constants.h"

#include "os.h"
#include "cx.h"

#define WALLET_TYPE_MULTISIG 0

typedef struct {
    uint8_t type; // Currently only the only supported value is WALLET_TYPE_MULTISIG
    uint8_t name_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];

    /*
        The remaining fields are specific to multisig wallets;
        this should be changed to a union when more wallet types are added.
    */
    uint8_t threshold;
    uint8_t n_keys;
} multisig_wallet_header_t;


/**
 * TODO: docs 
 */
int read_wallet_header(buffer_t *buffer, multisig_wallet_header_t *header);


/**
 * TODO: docs 
 */
void hash_update_append_wallet_header(cx_hash_t *hash_context, multisig_wallet_header_t *header);