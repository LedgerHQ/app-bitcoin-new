#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * This flow obtains and streams to the callback the preimage of a leaf of a Merkle tree, specified
 * by its index. If len_callback is not NONE, it is called before the other callback with the length
 * of the preimage (not including the 0x00 prefix).
 *
 * Returns a nagative number on failure, or the preimage length on success.
 */
int call_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                    const uint8_t merkle_root[static 32],
                                    uint32_t tree_size,
                                    uint32_t leaf_index,
                                    void (*len_callback)(size_t, void *),
                                    void (*callback)(buffer_t *, void *),
                                    void *callback_state);