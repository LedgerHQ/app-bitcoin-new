#pragma once

#include "os.h"
#include "cx.h"

#include "get_merkle_leaf_element.h"

#include "../../boilerplate/dispatcher.h"

// this flow aborts if any element is larger than this size
#define MAX_CHECK_MERKLE_TREE_PREIMAGE_SIZE 128

typedef struct {
    machine_context_t ctx;

    // input
    uint8_t root[20];
    size_t size;

    // outputs
    bool result; // true if the hash is correct, false otherwise

    // internal state
    size_t cur_el_idx;
    int cur_el_len;
    uint8_t cur_el[MAX_CHECK_MERKLE_TREE_PREIMAGE_SIZE];
    int prev_el_len;
    uint8_t prev_el[MAX_CHECK_MERKLE_TREE_PREIMAGE_SIZE];

    union {
        get_merkle_leaf_element_state_t get_merkle_leaf_element;
    } subcontext;
} check_merkle_tree_sorted_state_t;


/**
 * Given a Merkle tree root and the size of the tree, it requests all the elements to the client (verifying Merkle
 * proofs) and verifies that the leaf preimages are in lexicographical order.
 */
void flow_check_merkle_tree_sorted(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the get_merkle_preimage flow.
 * TODO: more precise docs
 */
static inline void call_check_merkle_tree_sorted(dispatcher_context_t *dispatcher_context,
                                   check_merkle_tree_sorted_state_t *flow_state,
                                   command_processor_t ret_proc,
                                   const uint8_t root[static 20],
                                   size_t size)
{
    memcpy(flow_state->root, root, 20);

    flow_state->size = size;

    dispatcher_context->start_flow(
        flow_check_merkle_tree_sorted,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
