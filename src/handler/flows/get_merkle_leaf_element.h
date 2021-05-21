#pragma once

#include "os.h"
#include "cx.h"

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "get_merkle_preimage.h"
#include "get_merkle_leaf_hash.h"

typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const uint8_t *merkle_root;
    uint32_t tree_size;
    uint32_t leaf_index;
    uint8_t *out_ptr;
    size_t out_ptr_len;

    size_t element_len;

    // internal state
    uint8_t leaf_hash[20];
    union {
        get_merkle_preimage_state_t get_merkle_preimage;
    } subcontext;
} get_merkle_leaf_element_state_t;


/**
 * TODO: docs
 */
void flow_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the get_merkle_leaf_element flow.
 * TODO: more precise docs
 */
static inline void call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                                get_merkle_leaf_element_state_t *flow_state,
                                                command_processor_t ret_proc,
                                                const uint8_t merkle_root[static 20],
                                                uint32_t tree_size,
                                                uint32_t leaf_index,
                                                uint8_t *out_ptr,
                                                size_t out_ptr_len)
{
    flow_state->merkle_root = merkle_root;
    flow_state->tree_size = tree_size;
    flow_state->leaf_index = leaf_index;
    flow_state->out_ptr = out_ptr;
    flow_state->out_ptr_len = out_ptr_len;

    dispatcher_context->start_flow(
        flow_get_merkle_leaf_element,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
