#pragma once

#include "../../boilerplate/dispatcher.h"

/**
 * TODO: docs
 */
int call_get_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                 const uint8_t merkle_root[static 32],
                                 uint32_t tree_size,
                                 uint32_t leaf_index,
                                 uint8_t *out_ptr,
                                 size_t out_ptr_len);
