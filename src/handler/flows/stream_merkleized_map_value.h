#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "../flows/get_merkle_leaf_index.h"
#include "../flows/stream_merkle_leaf_element.h"

typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;
    dispatcher_callback_descriptor_t callback;

    size_t value_len;

    // internal state
    uint8_t key_merkle_hash[20];

    union {
        get_merkle_leaf_index_state_t get_merkle_leaf_index;
        stream_merkle_leaf_element_state_t stream_merkle_leaf_element;
    } subcontext;
} stream_merkleized_map_value_state_t;


/**
 * Given a commitment to a merkleized key-value map, this flow find out the index of the corresponding element,
 * then it fetches it and it streams it back via the callback.
 * As the value is a Merkle tree preimage, it always start with a 0x00 byte.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to be done before.
 */
void flow_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline void call_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                                    stream_merkleized_map_value_state_t *flow_state,
                                                    command_processor_t ret_proc,
                                                    const merkleized_map_commitment_t *map,
                                                    const uint8_t *key,
                                                    int key_len,
                                                    dispatcher_callback_descriptor_t callback)
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;
    flow_state->callback = callback;

    dispatcher_context->start_flow(
        flow_stream_merkleized_map_value,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
