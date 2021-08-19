#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"

/**
 * Given a commitment to a merkleized key-value map, this flow finds out the index of the element
 * corresponding to the key, then fetches the hash of the corresponding value stores it in the `out`
 * pointer. As the value is a Merkle tree preimage, it is always the hash of a string starting with
 * a 0x00 byte.
 *
 * Returns a negative number if the key is not found, or any of the proofs failed. Returns 0 on
 * success.
 *
 * NOTE: this does _not_ check that the keys are lexicographically sorted; the sanity check needs to
 * be done before.\
 */
int call_get_merkleized_map_value_hash(dispatcher_context_t *dispatcher_context,
                                       const merkleized_map_commitment_t *map,
                                       const uint8_t *key,
                                       int key_len,
                                       uint8_t out[static 32]);