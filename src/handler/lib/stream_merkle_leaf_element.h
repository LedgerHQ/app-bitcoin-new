#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * This flow obtains and streams to the callback the preimage of a leaf of a Merkle tree, specified by its index.
 * Since leaves of a Merkle tree are prepended with a 0x00 prefix before hashing, the returned preimage always starts
 * with 0x00 (and is therefore 1 byte longer than the actual element's value).
 *
 * Returns a nagative number on failure, or the preimage length on success.
 */
int call_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                    const uint8_t merkle_root[static 20],
                                    uint32_t tree_size,
                                    uint32_t leaf_index,
                                    dispatcher_callback_descriptor_t callback);