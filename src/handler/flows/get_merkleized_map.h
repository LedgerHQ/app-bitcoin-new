#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "get_merkle_leaf_element.h"
#include "check_merkle_tree_sorted.h"

typedef struct {
    machine_context_t ctx;

    // input
    const uint8_t *root;
    int size;
    int index;
    merkleized_map_commitment_t *out_ptr;

    // internal state
    dispatcher_callback_descriptor_t keys_callback;

    uint8_t raw_output[9 + 2*20]; // maximum size of serialized result (9 bytes for the varint, and the 2 Merkle roots)

    union {
        get_merkle_leaf_element_state_t get_merkle_leaf_element;
        check_merkle_tree_sorted_state_t check_merkle_tree_sorted;
    } subcontext;
} get_merkleized_map_state_t;


/**
 * TODO
 */
void flow_get_merkleized_map(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline void call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                                         get_merkleized_map_state_t *flow_state,
                                                         command_processor_t ret_proc,
                                                         const uint8_t root[static 20],
                                                         int size,
                                                         int index,
                                                         dispatcher_callback_descriptor_t keys_callback,
                                                         merkleized_map_commitment_t *out_ptr)
{
    flow_state->root = root;
    flow_state->size = size;
    flow_state->index = index;
    flow_state->out_ptr = out_ptr;
    flow_state->keys_callback = keys_callback;

    dispatcher_context->start_flow(
        flow_get_merkleized_map,
        (machine_context_t *)flow_state,
        ret_proc
    );
}


/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline void call_get_merkleized_map(dispatcher_context_t *dispatcher_context,
                                           get_merkleized_map_state_t *flow_state,
                                           command_processor_t ret_proc,
                                           const uint8_t root[static 20],
                                           int size,
                                           int index,
                                           merkleized_map_commitment_t *out_ptr)
{
    call_get_merkleized_map_with_callback(dispatcher_context,
                                          flow_state,
                                          ret_proc,
                                          root,
                                          size,
                                          index,
                                          make_callback(NULL, NULL),
                                          out_ptr);
}
