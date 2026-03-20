#pragma once

/* Local headers */
#include "check_merkle_tree_sorted.h"
#include "dispatcher.h"
#include "merkle.h"

/**
 * Fetches the `index`-th element of a Merkle tree of merkleized maps, decodes it into `out_ptr`,
 * and verifies that the keys in the tree are lexicographically sorted. If `callback` is not `NULL`,
 * it is invoked once for each key element while checking the keys; `callback_state` is passed
 * through unchanged.
 *
 * Returns 0 on success, or a negative number if the leaf cannot be fetched, decoded, or validated.
 */
int call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                          void *callback_state,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          merkle_tree_elements_callback_t callback,
                                          merkleized_map_commitment_t *out_ptr);

/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline int call_get_merkleized_map(dispatcher_context_t *dispatcher_context,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          merkleized_map_commitment_t *out_ptr) {
    return call_get_merkleized_map_with_callback(dispatcher_context,
                                                 NULL,
                                                 root,
                                                 size,
                                                 index,
                                                 NULL,
                                                 out_ptr);
}
