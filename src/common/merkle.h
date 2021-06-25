
#pragma once

#include <stdint.h>

// TODO: RFC6962 defines the empty list hash as sha256(b''); while we're using 0 here. Should we change?

/*
  Implementation of Merkle proof verification. Follows RFC 6962: https://www.rfc-editor.org/rfc/pdfrfc/rfc6962.txt.pdf,
  using RIPEMD160 as the hash function.

  Namely (||| denodes concatenation):
  - leaf hashes for an element x are computed as RIPEMD160(0x00 ||| x)
  - internal element hashes for a note with left child hashing to l_hash and right child hashing to r_hash is:
    RIPEMD160(0x01 ||| l_hash ||| r_hash)

  This ensures that no two trees with the same root hash can be computed.

  Note that this implementation has 80 bits of collision-resistance security if the attacker can choose the value of
  leaves.
  If the attacker cannot control inserted leaves, then finding a collision is as hard as chosen-preimage for RIPEMD160.
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
 * Computes the hash for an internal node of the Merkle tree, given the hashes of its children.
 * The result is the output of RIPEMD160 on the concatenation of the byte 0x01, the left child hash, and the right
 * child hash.
 *
 * @param[in] left
 *   Pointer to the input buffer.
 * @param[in] right
 *   Length of the input buffer.
 * @param[out] out
 *   Pointer to a 20-bytes buffer to store the result.
 */
void merkle_combine_hashes(const uint8_t left[static 20], const uint8_t right[static 20], uint8_t out[static 20]);


/**
 * Computes the byte array indicating the directions of the elements in the path from the given leaf up to the root.
 * The length of the returned array is equal to the length of the Merkle proof for that leaf.
 * The i-th element of the resulting array is 0 if the i-th node in the Merkle path from the root is a left child,
 * 1 if it is a right child (the leaf itself is the 0-th element in such path; its parent is the 1-st element;
 * and so on).
 *
 * @param[in] size
 *   Number of leaves of the Merkle tree.
 * @param[in] index
 *   Index of a leaf of the Merkle tree.
 * @param[out] out
 *   Pointer to a 20-bytes buffer to store the result.
 * @param[in] out_len
 *   Length of the output array.
 *
 * @return the length of the Merkle proof (number of hashes) on success; a negative number on failure, that is if
 *         either size is 0, index is larger than size - 1, or out_len is smaller than the proof size.
 */
//int merkle_get_directions(size_t size, size_t index, uint8_t out[], size_t out_len);


/**
 * TODO: docs and tests
 */
int merkle_get_ith_direction(size_t size, size_t index, size_t i);

/**
 * Represents the Merkleized version of a key-value map, holding the number of elements, the root of the Merkle tree of the
 * sorted list of keys, and the root of the Merkle tree of the values (sorted by their correpsonding key).
 */
typedef struct {
  uint64_t size;
  uint8_t keys_root[20];
  uint8_t values_root[20];
} merkleized_map_commitment_t;