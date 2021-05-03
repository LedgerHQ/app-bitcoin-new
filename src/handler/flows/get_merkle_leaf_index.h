#pragma once

#include "get_merkle_leaf_hash.h"

#include "../../boilerplate/dispatcher.h"

// this flow aborts if any element is larger than this size
#define MAX_CHECK_MERKLE_TREE_PREIMAGE_SIZE 128

typedef struct {
    machine_context_t ctx;

    // input
    size_t size;
    const uint8_t *root;
    const uint8_t *leaf_hash;

    //output
    bool found;
    size_t index; 

    // internal state
    uint8_t returned_merkle_leaf_hash[20];
    union {
        get_merkle_leaf_hash_state_t get_merkle_leaf_hash;
    } subcontext;
} get_merkle_leaf_index_state_t;


/**
 * In this flow, we assume that the HWW knows:
 * Given Merkle root and the hash of a leaf, we ask the host to provide the index of a leaf with matching hash.
 * If multiple leaves have a matching hash, the host can return the index of any of them.
 */
void flow_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the get_merkle_preimage flow.
 * TODO: more precise docs
 */
static inline void call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                                              get_merkle_leaf_index_state_t *flow_state,
                                              command_processor_t ret_proc,
                                              size_t size,
                                              const uint8_t root[static 20],
                                              const uint8_t leaf_hash[static 20])
{
    flow_state->root = root;
    flow_state->leaf_hash = leaf_hash;
    flow_state->size = size;

    dispatcher_context->start_flow(
        flow_get_merkle_leaf_index,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
