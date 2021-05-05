#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "get_merkle_leaf_index.h"
#include "get_merkle_leaf_hash.h"

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
        get_merkle_leaf_hash_state_t get_merkle_leaf_hash;
    } subcontext;
} get_merkleized_map_value_hash_state_t;


/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element corresponding to the
 * key, then fetches the hash of the corresponding value stores it in the `out` pointer.
 * As the value is a Merkle tree preimage, it is always the hash of a string starting with a 0x00 byte.
 *
 * The flow will fail with SW_INCORRECT_DATA if the key is not found, or any of the proofs failed.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to be done before.\
 */
void flow_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map_value_hash flow.
 */
static inline void call_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context,
                                                      get_merkleized_map_value_hash_state_t *flow_state,
                                                      command_processor_t ret_proc,
                                                      const merkleized_map_commitment_t *map,
                                                      const uint8_t *key,
                                                      int key_len,
                                                      uint8_t out[static 20])
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;
    flow_state->out = out;

    dispatcher_context->start_flow(
        flow_get_merkleized_map_value_hash,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
