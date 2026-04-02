#pragma once

/* Local headers */
#include "dispatcher.h"

/**
 * Retrieves the index of the leaf whose hash is `leaf_hash` in the Merkle tree identified by
 * `root` and `size`.
 *
 * Returns the leaf index on success, or a negative value on failure. This function validates the
 * index returned by the host by retrieving the leaf hash at that index and checking that it matches
 * `leaf_hash`.
 */
int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 32],
                               const uint8_t leaf_hash[static 32]);
