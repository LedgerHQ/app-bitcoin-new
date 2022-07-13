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

#include "cx_ram.h"
#include "debug-helpers/debug.h"

void merkle_compute_element_hash(const uint8_t *in, size_t in_len, uint8_t out[static 32]) {
    cx_sha256_t hash;
    cx_sha256_init(&hash);

    // H(0x00 | in)
    crypto_hash_update_u8(&hash.header, 0x00);
    crypto_hash_update(&hash.header, in, in_len);

    crypto_hash_digest(&hash.header, out, 32);
}

// void merkle_combine_hashes(const uint8_t left[static 32],
//                            const uint8_t right[static 32],
//                            uint8_t out[static 32]) {
//     PRINT_STACK_POINTER();

//     cx_sha256_t hash;
//     cx_sha256_init(&hash);

//     // H(0x01 | left | right)
//     crypto_hash_update_u8(&hash.header, 0x01);
//     crypto_hash_update(&hash.header, left, 32);
//     crypto_hash_update(&hash.header, right, 32);

//     crypto_hash_digest(&hash.header, out, 32);
// }

// implementation using the cxram section, in order to save ram
void merkle_combine_hashes(const uint8_t left[static 32],
                           const uint8_t right[static 32],
                           uint8_t out[static 32]) {
    PRINT_STACK_POINTER();

    cx_sha256_init_no_throw(&G_cx.sha256);

    uint8_t prefix = 0x01;
    cx_sha256_update(&G_cx.sha256, &prefix, 1);

    cx_sha256_update(&G_cx.sha256, left, 32);
    cx_sha256_update(&G_cx.sha256, right, 32);

    cx_sha256_final(&G_cx.sha256, out);
    explicit_bzero(&G_cx.sha256, sizeof(cx_sha256_t));
}

// TODO: make this O(log n), or possibly O(1). Currently O(log^2 n).
int merkle_get_ith_direction(size_t size, size_t index, size_t i) {
    if (size <= 1 || index >= size) {
        return -1;
    }

    uint8_t n_directions = 0;
    while (size > 1) {
        uint8_t depth = ceil_lg(size);

        // bitmask of the direction from the current node, where 0 = left, 1 = right;
        // also the number of leaves of the left subtree
        uint32_t mask = 1 << (depth - 1);

        uint8_t is_right_child = (index & mask) != 0 ? 1 : 0;

        if (n_directions == i) {
            return is_right_child;
        }

        ++n_directions;

        if (is_right_child) {
            size -= mask;
            index -= mask;
        } else {
            size = mask;
        }
    }

    return -1;
}