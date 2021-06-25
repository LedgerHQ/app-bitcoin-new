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


// // TODO: Could return a bit-vector to save some memory.
// //       An alternative is to make a version to just compute the i-th element; easy to do in O(log n), can we do O(1)?
// int merkle_get_directions(size_t size, size_t index, uint8_t out[], size_t out_len) {
//     if (size == 0 || index >= size) {
//         return -1;
//     }

//     if (size == 1) {
//         return 0;
//     }

//     uint8_t n_directions = 0;
//     while (size > 1) {
//         if (out_len == n_directions) {
//             // already exhausted the output array, but we have more to add
//             return -2;
//         }

//         uint8_t depth = ceil_lg(size);

//         // bitmask of the direction from the current node, where 0 = left, 1 = right;
//         // also the number of leaves of the left subtree
//         uint32_t mask = 1 << (depth - 1);

//         uint8_t is_right_child = (index & mask) != 0 ? 1 : 0;
//         out[n_directions++] = is_right_child;

//         if (is_right_child) {
//             size -= mask;
//             index -= mask;
//         } else {
//             size = mask;
//         }

//         mask /= 2;
//     }

//     return n_directions;
// }
