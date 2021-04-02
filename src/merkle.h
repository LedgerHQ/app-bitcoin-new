
#pragma once

#include <stdint.h>

/**
 * The maximum depth supported for the Merkle tree, where the root has depth 0.
 * The maximum number of elements supported is therefore pow(2, MAX_MERKLE_TREE_DEPTH).
 */
#define MAX_MERKLE_TREE_DEPTH 32


/**
 * TODO: docs
 */
bool merkle_proof_verify(uint8_t root[static 20],
                         size_t size,
                         uint8_t element[static 20],
                         size_t index,
                         uint8_t (*proof)[20],
                         size_t proof_size);
