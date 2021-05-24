#pragma once

#include "os.h"
#include "cx.h"

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "stream_preimage.h"
#include "get_merkle_leaf_hash.h"

typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const uint8_t *merkle_root;
    uint32_t tree_size;
    uint32_t leaf_index;
    dispatcher_callback_descriptor_t callback;

    size_t element_len;

    // internal state
    uint8_t leaf_hash[20];
} stream_merkle_leaf_element_state_t;


/**
 * This flow obtains and streams to the callback the preimage of a leaf of a Merkle tree, specified by its index.
 * Since leaves of a Merkle tree are prepended with a 0x00 prefix before hashing, the returned preimage always starts
 * with 0x00 (and is therefore 1 byte longer than the actual element's value).
 */
void flow_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the stream_merkle_leaf_element flow.
 * TODO: more precise docs
 */
static inline void call_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                                   stream_merkle_leaf_element_state_t *flow_state,
                                                   command_processor_t ret_proc,
                                                   const uint8_t merkle_root[static 20],
                                                   uint32_t tree_size,
                                                   uint32_t leaf_index,
                                                   dispatcher_callback_descriptor_t callback)
{
    flow_state->merkle_root = merkle_root;
    flow_state->tree_size = tree_size;
    flow_state->leaf_index = leaf_index;
    flow_state->callback = callback;

    dispatcher_context->start_flow(
        flow_stream_merkle_leaf_element,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
