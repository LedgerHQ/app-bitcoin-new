#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * This flow requests a leaf hash from the Merkle tree, then it requests and verifies its preimage.
 *
 * Returns the length of the preimage, or a negative number in case of error.
 */
int call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                 const uint8_t merkle_root[static 20],
                                 uint32_t tree_size,
                                 uint32_t leaf_index,
                                 uint8_t *out_ptr,
                                 size_t out_ptr_len);

