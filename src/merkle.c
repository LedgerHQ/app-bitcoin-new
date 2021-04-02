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

#include "crypto.h"

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


static void combine_hashes(uint8_t left[20], uint8_t right[20], uint8_t out[]) {
    cx_ripemd160_t rip_context;
    cx_ripemd160_init(&rip_context);
    cx_hash(&rip_context.header, 0, left, 20, NULL, 0);
    cx_hash(&rip_context.header, CX_LAST, right, 20, out, 20);
}


static int get_directions(size_t size, size_t index, uint8_t out[], size_t out_len) {
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

// TODO: add tests
bool merkle_proof_verify(uint8_t root[static 20], size_t size, uint8_t element[static 20], size_t index, uint8_t (*proof)[20], size_t proof_size) {
    uint8_t cur_hash[20];
    memcpy(cur_hash, element, sizeof(cur_hash));

    uint8_t directions[MAX_MERKLE_TREE_DEPTH];
    uint8_t n_directions = get_directions(size, index, directions, sizeof(directions));
    if (proof_size != n_directions) {
        return false;
    }

    for (int i = n_directions - 1; i >= 0; i--) {
        if (directions[i] == 0) {
            combine_hashes(cur_hash, proof[i], cur_hash);
        } else {
            combine_hashes(proof[i], cur_hash, cur_hash);
        }
    }

    return memcmp(&cur_hash, root, 20) == 0;
}