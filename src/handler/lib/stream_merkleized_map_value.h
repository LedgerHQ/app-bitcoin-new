#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow find out the index of the corresponding element,
 * then it fetches it and it streams it back via the callback.
 *
 * Returns a negative number on failure, or the preimage length on success.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to be done before.
 */
int call_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                     const merkleized_map_commitment_t *map,
                                     const uint8_t *key,
                                     int key_len,
                                     void (*callback)(buffer_t *, void *),
                                     void *callback_state);