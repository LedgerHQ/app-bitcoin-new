#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "get_merkle_leaf_index.h"
#include "get_merkle_leaf_element.h"

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
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element corresponding to the
 * key, then fetches the corresponding element and verifies that its hash and Merkle proof matches. The value is then
 * stored in the `out` pointer, which must be large enough to contain the preimage.
 * As the value is a Merkle tree preimage, it always start with a 0x00 byte.
 * In case of success, the length of the preimage (including the 0x00 byte) is stored in value_len at the end of the
 * flow.
 *
 * The flow will fail with SW_WRONG_DATA_LENGTH if the response is too long to fit into the output buffer, and with
 * SW_INCORRECT_DATA if the key is not found, or any of the proofs failed.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to be done before.
 */
void flow_get_merkleized_map_value(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map_value flow.
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
