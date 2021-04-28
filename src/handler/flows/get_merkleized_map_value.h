#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "../flows/get_merkle_leaf_index.h"
#include "../flows/get_merkle_leaf_element.h"

typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;
    uint8_t *out;
    size_t out_len;

    size_t value_len;

    // internal state
    uint8_t key_merkle_hash[20];

    union {
        get_merkle_leaf_index_state_t get_merkle_leaf_index;
        get_merkle_leaf_element_state_t get_merkle_leaf_element;
    } subcontext;
} get_merkleized_map_value_state_t;


/**
 * TODO
 */
void flow_get_merkleized_map_value(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline void call_get_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                                 get_merkleized_map_value_state_t *flow_state,
                                                 command_processor_t ret_proc,
                                                 const merkleized_map_commitment_t *map,
                                                 const uint8_t *key,
                                                 int key_len,
                                                 uint8_t *out,
                                                 int out_len)
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;
    flow_state->out = out;
    flow_state->out_len = out_len;

    dispatcher_context->start_flow(
        flow_get_merkleized_map_value,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
