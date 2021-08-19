#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * TODO: docs
 */
int call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          dispatcher_callback_descriptor_t keys_callback,
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
                                                 root,
                                                 size,
                                                 index,
                                                 make_callback(NULL, NULL),
                                                 out_ptr);
}
