#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * TODO: docs
 */
int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 32],
                               const uint8_t leaf_hash[static 32]);