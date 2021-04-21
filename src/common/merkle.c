/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool

#include "buffer.h"
#include "../crypto.h"

#include "merkle.h"

static uint8_t ceil_lg(uint32_t n) {
    uint8_t r = 0;
    uint32_t t = 1;
    while (t < n) {
        t = 2 * t;
        ++r;
    }
    return r;
}


void merkle_compute_element_hash(const uint8_t *in, size_t in_len, uint8_t out[static 20]) {
    cx_ripemd160_t rip_context;
    cx_ripemd160_init(&rip_context);

    // H(0x00 | in)
    crypto_hash_update_u8(&rip_context.header, 0x00);
    crypto_hash_update(&rip_context.header, in, in_len);

    crypto_hash_digest(&rip_context.header, out, 20);
}


void merkle_combine_hashes(const uint8_t left[static 20], const uint8_t right[static 20], uint8_t out[static 20]) {
    cx_ripemd160_t rip_context;
    cx_ripemd160_init(&rip_context);

    // H(0x01 | left | right)
    crypto_hash_update_u8(&rip_context.header, 0x01);
    crypto_hash_update(&rip_context.header, left, 20);
    crypto_hash_update(&rip_context.header, right, 20);

    crypto_hash_digest(&rip_context.header, out, 20);
}


int merkle_get_directions(size_t size, size_t index, uint8_t out[], size_t out_len) {
    if (size == 0 || index >= size) {
        return -1;
    }

    if (size == 1) {
        return 0;
    }

    uint8_t n_directions = 0;
    while (size > 1) {
        if (out_len == n_directions) {
            // already exhausted the output array, but we have more to add
            return -2;
        }

        uint8_t depth = ceil_lg(size);

        // bitmask of the direction from the current node, where 0 = left, 1 = right;
        // also the number of leaves of the left subtree
        uint32_t mask = 1 << (depth - 1);

        uint8_t is_right_child = (index & mask) != 0 ? 1 : 0;
        out[n_directions++] = is_right_child;

        if (is_right_child) {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }

        mask /= 2;
    }

    return n_directions;
}


// TODO: delete once get_wallet_address is refactored

// size:      4
// index:     4
// proof_len: 1
// proof:     20 * proof_len
bool buffer_read_and_verify_merkle_proof(buffer_t *buffer,
                                         const uint8_t root[static 20],
                                         size_t size,
                                         size_t index,
                                         const uint8_t element_hash[static 20]) {
    if (!buffer_can_read(buffer, 4+4+1)) { // size, index and proof_len
        return false;
    }
    uint8_t proof_len;

    if (index >= size || size == 0) {
        PRINTF("bravmp: Wrong index or size: %u, %u\n", index, size);
        return false;
    }
    buffer_read_u8(buffer, &proof_len);

    uint8_t cur_hash[20];
    memcpy(cur_hash, element_hash, sizeof(cur_hash));

    uint8_t directions[MAX_MERKLE_TREE_DEPTH];
    int n_directions = merkle_get_directions(size, index, directions, sizeof(directions));
    if (n_directions == -1 || proof_len != n_directions) {
        PRINTF("bravmp: Wrong proof_len: %d. Should be: %d\n", proof_len, n_directions);
        return false;
    }

    if (!buffer_can_read(buffer, 20 * proof_len)) {
        PRINTF("bravmp: Buffer too short.\n");
        return false; // not enough bytes in the stream
    }

    for (int i = proof_len - 1; i >= 0; i--) {
        uint8_t sibling_hash[20];
        buffer_read_bytes(buffer, sibling_hash, 20);

        if (directions[i] == 0) {
            merkle_combine_hashes(cur_hash, sibling_hash, cur_hash);
        } else {
            merkle_combine_hashes(sibling_hash, cur_hash, cur_hash);
        }
    }

    bool result = memcmp(&cur_hash, root, 20) == 0;

    if (!result) PRINTF("bravmp: Root hash not matching.\n");

    return result;
}
