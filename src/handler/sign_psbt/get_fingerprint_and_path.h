#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../common/wallet.h"

/**
 * TODO
 */
int get_fingerprint_and_path(dispatcher_context_t *dispatcher_context,
                             const merkleized_map_commitment_t *map,
                             const uint8_t *key,
                             int key_len,
                             uint32_t *out_fingerprint,
                             uint32_t out_bip32_path[static MAX_BIP32_PATH_STEPS]);