#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * Call the get_merkle_preimage flow.
 * TODO: more precise docs
 */
int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 20],
                               const uint8_t leaf_hash[static 20]);