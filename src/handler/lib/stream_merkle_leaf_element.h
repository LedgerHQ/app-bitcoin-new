#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * This flow obtains and streams to the callback the preimage of a leaf of a Merkle tree, specified by its index.
 *
 * Returns a nagative number on failure, or the preimage length on success.
 */
int call_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                    const uint8_t merkle_root[static 20],
                                    uint32_t tree_size,
                                    uint32_t leaf_index,
                                    void (*callback)(buffer_t *, void *),
                                    void *callback_state);