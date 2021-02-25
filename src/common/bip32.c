/*****************************************************************************
 *   (c) 2020 Ledger SAS.
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

#include <stdio.h>    // snprintf
#include <string.h>   // memset, strlen
#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "bip32.h"
#include "read.h"

bool bip32_path_read(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len) {
    if (out_len == 0 || out_len > MAX_BIP32_PATH) {
        return false;
    }

    size_t offset = 0;

    for (size_t i = 0; i < out_len; i++) {
        if (offset > in_len) {
            return false;
        }
        out[i] = read_u32_be(in, offset);
        offset += 4;
    }

    return true;
}

bool bip32_path_format(const uint32_t *bip32_path,
                       size_t bip32_path_len,
                       char *out,
                       size_t out_len) {
    if (bip32_path_len == 0 || bip32_path_len > MAX_BIP32_PATH) {
        return false;
    }

    size_t offset = 0;

    for (uint16_t i = 0; i < bip32_path_len; i++) {
        size_t written;

        snprintf(out + offset, out_len - offset, "%d", bip32_path[i] & 0x7FFFFFFFu);
        written = strlen(out + offset);
        if (written == 0 || written >= out_len - offset) {
            memset(out, 0, out_len);
            return false;
        }
        offset += written;

        if ((bip32_path[i] & 0x80000000u) != 0) {
            snprintf(out + offset, out_len - offset, "'");
            written = strlen(out + offset);
            if (written == 0 || written >= out_len - offset) {
                memset(out, 0, out_len);
                return false;
            }
            offset += written;
        }

        if (i != bip32_path_len - 1) {
            snprintf(out + offset, out_len - offset, "/");
            written = strlen(out + offset);
            if (written == 0 || written >= out_len - offset) {
                memset(out, 0, out_len);
                return false;
            }
            offset += written;
        }
    }

    return true;
}
