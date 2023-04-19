#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

// this flow aborts if any element is larger than this size
// This is enough for a PSBT with the control block of a taptree of depth 5 tapbranches
// TODO: we might remove this limitation altogether with a more careful implementation.
#define MAX_CHECK_MERKLE_TREE_SORTED_PREIMAGE_SIZE 162

typedef void (*merkle_tree_elements_callback_t)(struct dispatcher_context_s *,
                                                void *,
                                                const merkleized_map_commitment_t *,
                                                int,
                                                buffer_t *);

/**
 * Given a Merkle tree root and the size of the tree, it requests all the elements to the client
 * (verifying Merkle proofs) and verifies that the leaf preimages are in lexicographical order. If a
 * callback to a non-NULL function is given, it is called once for each of the elements of the
 * Merkle tree, in lexicographical order.
 *
 * Returns 0 on success, or a negative number on failure.
 */
int call_check_merkle_tree_sorted_with_callback(dispatcher_context_t *dispatcher_context,
                                                void *callback_state,
                                                const uint8_t root[static 32],
                                                size_t size,
                                                merkle_tree_elements_callback_t callback,
                                                const merkleized_map_commitment_t *map_commitment);

/**
 * Convenience function to call the get_merkle_tree_sorted flow, with a void callback.
 */
static inline int call_check_merkle_tree_sorted(dispatcher_context_t *dispatcher_context,
                                                const uint8_t root[static 32],
                                                size_t size) {
    return call_check_merkle_tree_sorted_with_callback(dispatcher_context,
                                                       NULL,
                                                       root,
                                                       size,
                                                       NULL,
                                                       NULL);
}