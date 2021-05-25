#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element corresponding to the
 * key, then fetches the corresponding element and verifies that its hash and Merkle proof matches. The value is then
 * stored in the `out` pointer, which must be large enough to contain the preimage.
 * As the value is a Merkle tree preimage, it always start with a 0x00 byte.
 * In case of success, the length of the preimage (including the 0x00 byte) is stored in value_len at the end of the
 * flow.
 *
 * Returns a negative number if the response is too long to fit into the output buffer, or if the key is not found,
 * or if any of the proofs failed. Returns the length of the preimage (including the 0x00 prefix) on success.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to be done before.
 */
int call_get_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                  const merkleized_map_commitment_t *map,
                                  const uint8_t *key,
                                  int key_len,
                                  uint8_t *out,
                                  int out_len);
