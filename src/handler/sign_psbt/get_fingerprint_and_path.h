#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../common/wallet.h"

/**
 * Used to read PSBT_IN_BIP32_DERIVATION or PSBT_OUT_BIP32_DERIVATION entries from a PSBT map.
 * Returns the length of the BIP32 path on success, a negative number on failure.
 *
 * TODO: more precise docs
 */
int get_fingerprint_and_path(dispatcher_context_t *dispatcher_context,
                             const merkleized_map_commitment_t *map,
                             const uint8_t *key,
                             int key_len,
                             uint32_t *out_fingerprint,
                             uint32_t out_bip32_path[static MAX_BIP32_PATH_STEPS]);

/**
 * Used to read PSBT_IN_TAP_BIP32_DERIVATION or PSBT_OUT_TAP_BIP32_DERIVATION entries from a PSBT
 * map; fails if the hashes_len is not 0 (only useful for keypath spending).
 * Returns the length of the BIP32 path on success, a negative number on failure.
 *
 * TODO: more precise docs
 */
int get_emptyhashes_fingerprint_and_path(dispatcher_context_t *dispatcher_context,
                                         const merkleized_map_commitment_t *map,
                                         const uint8_t *key,
                                         int key_len,
                                         uint32_t *out_fingerprint,
                                         uint32_t out_bip32_path[static MAX_BIP32_PATH_STEPS]);