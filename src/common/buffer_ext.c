/*****************************************************************************
 *   (c) 2026 Ledger SAS.
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
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "lib_standard_app/buffer.h"
#include "buffer_ext.h"
#include "read.h"
#include "varint.h"
#include "bip32.h"

bool buffer_peek(const buffer_t *buffer, uint8_t *value) {
    return buffer_peek_n(buffer, 0, value);
}

bool buffer_peek_n(const buffer_t *buffer, size_t n, uint8_t *value) {
    if (!buffer_can_read(buffer, n + 1)) {
        return false;
    }

    *value = buffer->ptr[buffer->offset + n];

    return true;
}

bool buffer_read_bytes(buffer_t *buffer, uint8_t *out, size_t n) {
    if (buffer->size - buffer->offset < n) {
        return false;
    }

    memmove(out, buffer->ptr + buffer->offset, n);
    buffer_seek_cur(buffer, n);

    return true;
}

bool buffer_write_bytes(buffer_t *buffer, const uint8_t *data, size_t n) {
    if (!buffer_can_read(buffer, n)) {
        return false;
    }

    memmove((uint8_t *) (buffer->ptr + buffer->offset), data, n);
    buffer_seek_cur(buffer, n);
    return true;
}

void *buffer_alloc(buffer_t *buffer, size_t size, bool aligned) {
    size_t padding_size = 0;

    if (aligned) {
        uint32_t d = (uint32_t) (buffer->ptr + buffer->offset) % 4;
        if (d != 0) {
            padding_size = 4 - d;
        }
    }

    if (!buffer_can_read(buffer, padding_size + size)) {
        return NULL;
    }

    void *result = (uint8_t *) (buffer->ptr + buffer->offset) + padding_size;
    buffer_seek_cur(buffer, padding_size + size);
    return result;
}
