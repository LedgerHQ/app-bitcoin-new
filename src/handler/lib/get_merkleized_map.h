#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

#include "check_merkle_tree_sorted.h"

/**
 * TODO: docs
 */
int call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                          machine_context_t *state,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          merkle_tree_elements_callback_t callback,
                                          merkleized_map_commitment_t *out_ptr);

/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline int call_get_merkleized_map(dispatcher_context_t *dispatcher_context,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          merkleized_map_commitment_t *out_ptr) {
    return call_get_merkleized_map_with_callback(dispatcher_context,
                                                 NULL,
                                                 root,
                                                 size,
                                                 index,
                                                 NULL,
                                                 out_ptr);
}
