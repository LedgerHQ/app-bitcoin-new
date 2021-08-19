#pragma once

#include "../../boilerplate/dispatcher.h"

// this flow aborts if any element is larger than this size
// In PSBT, keys are currently up to 1+78 (for a serialized extended public key).
#define MAX_CHECK_MERKLE_TREE_SORTED_PREIMAGE_SIZE 80

/**
 * Given a Merkle tree root and the size of the tree, it requests all the elements to the client
 * (verifying Merkle proofs) and verifies that the leaf preimages are in lexicographical order. If a
 * callback to a non-NULL function is given, it is called once for each of the elements of the
 * Merkle tree, in lexicographical order.
 *
 * Returns 0 on success, or a negative number on failure.
 */
int call_check_merkle_tree_sorted_with_callback(dispatcher_context_t *dispatcher_context,
                                                const uint8_t root[static 32],
                                                size_t size,
                                                dispatcher_callback_descriptor_t callback);

/**
 * Convenience function to call the get_merkle_tree_sorted flow, with a void callback.
 */
static inline int call_check_merkle_tree_sorted(dispatcher_context_t *dispatcher_context,
                                                const uint8_t root[static 32],
                                                size_t size) {
    return call_check_merkle_tree_sorted_with_callback(dispatcher_context,
                                                       root,
                                                       size,
                                                       make_callback(NULL, NULL));
}