#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * Streams the requested preimage from a merkleized map, updating the given has contexts
 * appropriately. Both hash_unprefixed and hash_prefixed are optional, but if not NULL, it is
 * responsibility of the caller to ensure that they are initialized.
 *
 * If hash_unprefixed is not NULL, it is updated with the preimage bytes.
 * If hash_unprefixed is not NULL, it is updated with the premiage length serialized as a
 * Bitcoin-style varint, followed by the preimage bytes.
 *
 * Returns the length of the preimage on success, or -1 in case of error.
 */
int update_hashes_with_map_value(dispatcher_context_t *dispatcher_context,
                                 const merkleized_map_commitment_t *map,
                                 const uint8_t *key,
                                 int key_len,
                                 cx_hash_t *hash_unprefixed,
                                 cx_hash_t *hash_prefixed);