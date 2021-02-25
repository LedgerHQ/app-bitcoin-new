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

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <string.h>   // memmove, memset
#include <stdbool.h>  // bool

#include "base58.h"

uint8_t const BASE58_TABLE[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  //
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF,  //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,  //
    0x10, 0xFF, 0x11, 0x12, 0x13, 0x14, 0x15, 0xFF, 0x16, 0x17, 0x18, 0x19,  //
    0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  //
    0xFF, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,  //
    0xFF, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,  //
    0x37, 0x38, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF                           //
};

char const BASE58_ALPHABET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',  //
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',  //
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',  //
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'             //
};

int base58_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len) {
    uint8_t tmp[MAX_DEC_INPUT_SIZE] = {0};
    uint8_t buffer[MAX_DEC_INPUT_SIZE] = {0};
    uint8_t j;
    uint8_t start_at;
    uint8_t zero_count = 0;

    if (in_len > MAX_DEC_INPUT_SIZE || in_len < 2) {
        return -1;
    }

    memmove(tmp, in, in_len);

    for (uint8_t i = 0; i < in_len; i++) {
        if (in[i] >= sizeof(BASE58_TABLE)) {
            return -1;
        }

        tmp[i] = BASE58_TABLE[(int) in[i]];

        if (tmp[i] == 0xFF) {
            return -1;
        }
    }

    while ((zero_count < in_len) && (tmp[zero_count] == 0)) {
        ++zero_count;
    }

    j = in_len;
    start_at = zero_count;
    while (start_at < in_len) {
        uint16_t remainder = 0;
        for (uint8_t div_loop = start_at; div_loop < in_len; div_loop++) {
            uint16_t digit256 = (uint16_t)(tmp[div_loop] & 0xFF);
            uint16_t tmp_div = remainder * 58 + digit256;
            tmp[div_loop] = (uint8_t)(tmp_div / 256);
            remainder = tmp_div % 256;
        }

        if (tmp[start_at] == 0) {
            ++start_at;
        }

        buffer[--j] = (uint8_t) remainder;
    }

    while ((j < in_len) && (buffer[j] == 0)) {
        ++j;
    }

    int length = in_len - (j - zero_count);

    if ((int) out_len < length) {
        return -1;
    }

    memmove(out, buffer + j - zero_count, length);

    return length;
}

int base58_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    uint8_t buffer[MAX_ENC_INPUT_SIZE * 138 / 100 + 1] = {0};
    size_t i, j;
    size_t stop_at;
    size_t zero_count = 0;
    size_t output_size;

    if (in_len > MAX_ENC_INPUT_SIZE) {
        return -1;
    }

    while ((zero_count < in_len) && (in[zero_count] == 0)) {
        ++zero_count;
    }

    output_size = (in_len - zero_count) * 138 / 100 + 1;
    stop_at = output_size - 1;
    for (size_t start_at = zero_count; start_at < in_len; start_at++) {
        int carry = in[start_at];
        for (j = output_size - 1; (int) j >= 0; j--) {
            carry += 256 * buffer[j];
            buffer[j] = carry % 58;
            carry /= 58;

            if (j <= stop_at - 1 && carry == 0) {
                break;
            }
        }
        stop_at = j;
    }

    j = 0;
    while (j < output_size && buffer[j] == 0) {
        j += 1;
    }

    if (out_len < zero_count + output_size - j) {
        return -1;
    }

    memset(out, BASE58_ALPHABET[0], zero_count);

    i = zero_count;
    while (j < output_size) {
        out[i++] = BASE58_ALPHABET[buffer[j++]];
    }

    return i;
}
