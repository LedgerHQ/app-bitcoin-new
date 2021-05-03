#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const uint8_t *merkle_root;
    uint32_t tree_size;
    uint32_t leaf_index;

    uint8_t *out;

    // internal state
    uint8_t cur_hash[20]; // temporary buffer for intermediate hashes
    int proof_size;
    int cur_step;             // counter for the proof steps

    uint8_t directions[MAX_MERKLE_TREE_DEPTH];
} get_merkle_leaf_hash_state_t;


/**
 * TODO
 */
void flow_get_merkle_leaf_hash(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the get_merkle_preimage flow.
 * TODO: more precise docs
 */
static inline void call_get_merkle_leaf_hash(dispatcher_context_t *dispatcher_context,
                                             get_merkle_leaf_hash_state_t *flow_state,
                                             command_processor_t ret_proc,
                                             const uint8_t merkle_root[static 20],
                                             uint32_t tree_size,
                                             uint32_t leaf_index,
                                             uint8_t out[static 20])
{
    flow_state->merkle_root = merkle_root;
    flow_state->tree_size = tree_size;
    flow_state->leaf_index = leaf_index;
    flow_state->out = out;
    dispatcher_context->start_flow(
        flow_get_merkle_leaf_hash,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
