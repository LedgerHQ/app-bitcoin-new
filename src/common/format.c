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
#include <stdint.h>   // int*_t, uint*_t
#include <string.h>   // strncpy, memmove
#include <stdbool.h>  // bool

#include "format.h"

bool format_i64(char *dst, size_t dst_len, const int64_t value) {
    char temp[] = "-9223372036854775808";

    char *ptr = temp;
    int64_t num = value;
    int sign = 1;

    if (value < 0) {
        sign = -1;
    }

    while (num != 0) {
        *ptr++ = '0' + (num % 10) * sign;
        num /= 10;
    }

    if (value < 0) {
        *ptr++ = '-';
    } else if (value == 0) {
        *ptr++ = '0';
    }

    int distance = (ptr - temp) + 1;

    if ((int) dst_len < distance) {
        return false;
    }

    size_t index = 0;

    while (--ptr >= temp) {
        dst[index++] = *ptr;
    }

    dst[index] = '\0';

    return true;
}

bool format_u64(char *out, size_t outLen, uint64_t in) {
    uint8_t i = 0;

    if (outLen == 0) {
        return false;
    }
    outLen--;

    while (in > 9) {
        out[i] = in % 10 + '0';
        in /= 10;
        i++;
        if (i + 1 > outLen) {
            return false;
        }
    }
    out[i] = in + '0';
    out[i + 1] = '\0';

    uint8_t j = 0;
    char tmp;

    // revert the string
    while (j < i) {
        // swap out[j] and out[i]
        tmp = out[j];
        out[j] = out[i];
        out[i] = tmp;

        i--;
        j++;
    }
    return true;
}

bool format_fpu64(char *dst, size_t dst_len, const uint64_t value, uint8_t decimals) {
    char buffer[21] = {0};

    if (!format_u64(buffer, sizeof(buffer), value)) {
        return false;
    }

    size_t digits = strlen(buffer);

    if (digits <= decimals) {
        if (dst_len <= 2 + decimals - digits) {
            return false;
        }
        *dst++ = '0';
        *dst++ = '.';
        for (uint16_t i = 0; i < decimals - digits; i++, dst++) {
            *dst = '0';
        }
        dst_len -= 2 + decimals - digits;
        strncpy(dst, buffer, dst_len);
    } else {
        if (dst_len <= digits + 1 + decimals) {
            return false;
        }

        const size_t shift = digits - decimals;
        memmove(dst, buffer, shift);
        dst[shift] = '.';
        strncpy(dst + shift + 1, buffer + shift, decimals);
    }

    return true;
}

int format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    if (out_len < 2 * in_len + 1) {
        return -1;
    }

    const char hex[] = "0123456789ABCDEF";
    size_t i = 0;
    int written = 0;

    while (i < in_len && (i * 2 + (2 + 1)) <= out_len) {
        uint8_t high_nibble = (in[i] & 0xF0) >> 4;
        *out = hex[high_nibble];
        out++;

        uint8_t low_nibble = in[i] & 0x0F;
        *out = hex[low_nibble];
        out++;

        i++;
        written += 2;
    }

    *out = '\0';

    return written + 1;
}
