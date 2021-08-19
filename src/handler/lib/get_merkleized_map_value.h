#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../common/read.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element
 * corresponding to the key, then fetches the corresponding element and verifies that its hash and
 * Merkle proof matches. The value is then stored in the `out` pointer, which must be large enough
 * to contain the preimage.
 *
 * Returns a negative number if the response is too long to fit into the output buffer, or if the
 * key is not found, or if any of the proofs failed. Returns the length of the preimage on success.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to
 * be done before.
 */
int call_get_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                  const merkleized_map_commitment_t *map,
                                  const uint8_t *key,
                                  int key_len,
                                  uint8_t *out,
                                  int out_len);

/**
 * Convenience shortcut to read a little-endian unsigned 32-bit int.
 * TODO: more docs
 */
static inline int call_get_merkleized_map_value_u32_le(dispatcher_context_t *dispatcher_context,
                                                       const merkleized_map_commitment_t *map,
                                                       const uint8_t *key,
                                                       int key_len,
                                                       uint32_t *out) {
    uint8_t result_raw[4];

    int res = call_get_merkleized_map_value(dispatcher_context, map, key, key_len, result_raw, 4);
    if (res != 4) {
        return -1;
    }

    *out = read_u32_le(result_raw, 0);

    return 4;
}