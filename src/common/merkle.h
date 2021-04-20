
#pragma once

#include <stdint.h>

/*
  Implementation of Merkle proof verification. Follows RFC 6962: https://www.rfc-editor.org/rfc/pdfrfc/rfc6962.txt.pdf,
  using RIPEMD160 as the hash function.

  Namely (||| denodes concatenation):
  - leaf hashes for an element x are computed as RIPEMD160(0x00 ||| x)
  - internal element hashes for a note with left child hashing to l_hash and right child hashing to r_hash is:
    RIPEMD160(0x01 ||| l_hash ||| r_hash)

  This ensures that no two trees with the same root hash can be computed.

  Note that this implementation has 80 bits of collision-resistance security if the attacker can choose leafs.
  If the attacker cannot control inserted leafs, then finding a collision is as hard as chosen-preimage for RIPEMD160.
*/

/**
 * The maximum depth supported for the Merkle tree, where the root has depth 0.
 * The maximum number of elements supported is therefore pow(2, MAX_MERKLE_TREE_DEPTH).
 */
#define MAX_MERKLE_TREE_DEPTH 32


/**
 * Convenience method to compute the hash of an element for the Merkle tree, which is the RIPEMD160 hash of the
 * input buffer, prepended with a 0x00 byte.
 *
 * @param[in] in
 *   Pointer to the input buffer.
 * @param[in] in_len
 *   Length of the input buffer.
 * @param[out] out
 *   Pointer to a 20-bytes buffer to store the result.
 */
void merkle_compute_element_hash(const uint8_t *in, size_t in_len, uint8_t out[static 20]);


/**
 * TODO: docs
 */
bool merkle_proof_verify(uint8_t root[static 20],
                         size_t size,
                         uint8_t element_hash[static 20],
                         size_t index,
                         uint8_t (*proof)[20],
                         size_t proof_size);


/**
 * TODO: docs
 */
bool buffer_read_and_verify_merkle_proof(
    buffer_t *buffer,
    const uint8_t root[static 20],
    size_t size,
    size_t index,
    const uint8_t element_hash[static 20]);
