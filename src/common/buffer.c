/*****************************************************************************
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
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "buffer.h"
#include "read.h"
#include "write.h"
#include "varint.h"
#include "bip32.h"

bool buffer_can_read(const buffer_t *buffer, size_t n) {
    return buffer->size - buffer->offset >= n;
}

bool buffer_seek_set(buffer_t *buffer, size_t offset) {
    if (offset > buffer->size) {
        return false;
    }

    buffer->offset = offset;

    return true;
}

bool buffer_seek_cur(buffer_t *buffer, size_t offset) {
    if (buffer->offset + offset < buffer->offset ||  // overflow
        buffer->offset + offset > buffer->size) {    // exceed buffer size
        return false;
    }

    buffer->offset += offset;

    return true;
}

bool buffer_seek_end(buffer_t *buffer, size_t offset) {
    if (offset > buffer->size) {
        return false;
    }

    buffer->offset = buffer->size - offset;

    return true;
}

bool buffer_read_u8(buffer_t *buffer, uint8_t *value) {
    if (!buffer_can_read(buffer, 1)) {
        *value = 0;

        return false;
    }

    *value = buffer->ptr[buffer->offset];
    buffer_seek_cur(buffer, 1);

    return true;
}

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

bool buffer_read_u16(buffer_t *buffer, uint16_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 2)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u16_be(buffer->ptr, buffer->offset)
                                 : read_u16_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 2);

    return true;
}

bool buffer_read_u32(buffer_t *buffer, uint32_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 4)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u32_be(buffer->ptr, buffer->offset)
                                 : read_u32_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 4);

    return true;
}

bool buffer_read_u64(buffer_t *buffer, uint64_t *value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 8)) {
        *value = 0;

        return false;
    }

    *value = ((endianness == BE) ? read_u64_be(buffer->ptr, buffer->offset)
                                 : read_u64_le(buffer->ptr, buffer->offset));

    buffer_seek_cur(buffer, 8);

    return true;
}

bool buffer_read_varint(buffer_t *buffer, uint64_t *value) {
    int length = varint_read(buffer->ptr + buffer->offset, buffer->size - buffer->offset, value);

    if (length < 0) {
        *value = 0;

        return false;
    }

    buffer_seek_cur(buffer, (size_t) length);

    return true;
}

bool buffer_read_bip32_path(buffer_t *buffer, uint32_t *out, size_t out_len) {
    if (!bip32_path_read(buffer->ptr + buffer->offset,
                         buffer->size - buffer->offset,
                         out,
                         out_len)) {
        return false;
    }

    buffer_seek_cur(buffer, sizeof(*out) * out_len);

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

bool buffer_write_u8(buffer_t *buffer, uint8_t value) {
    if (!buffer_can_read(buffer, 1)) {
        return false;
    }

    buffer->ptr[buffer->offset] = value;
    buffer_seek_cur(buffer, 1);

    return true;
}

bool buffer_write_u16(buffer_t *buffer, uint16_t value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 2)) {
        return false;
    }

    if (endianness == BE) {
        write_u16_be(buffer->ptr, buffer->offset, value);
    } else {
        write_u16_le(buffer->ptr, buffer->offset, value);
    }
    buffer_seek_cur(buffer, 2);

    return true;
}

bool buffer_write_u32(buffer_t *buffer, uint32_t value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 4)) {
        return false;
    }

    if (endianness == BE) {
        write_u32_be(buffer->ptr, buffer->offset, value);
    } else {
        write_u32_le(buffer->ptr, buffer->offset, value);
    }
    buffer_seek_cur(buffer, 4);

    return true;
}

bool buffer_write_u64(buffer_t *buffer, uint64_t value, endianness_t endianness) {
    if (!buffer_can_read(buffer, 8)) {
        return false;
    }

    if (endianness == BE) {
        write_u64_be(buffer->ptr, buffer->offset, value);
    } else {
        write_u64_le(buffer->ptr, buffer->offset, value);
    }

    buffer_seek_cur(buffer, 8);

    return true;
}

bool buffer_write_bytes(buffer_t *buffer, const uint8_t *data, size_t n) {
    if (!buffer_can_read(buffer, n)) {
        return false;
    }

    memmove(buffer->ptr + buffer->offset, data, n);
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

    void *result = buffer->ptr + buffer->offset + padding_size;
    buffer_seek_cur(buffer, padding_size + size);
    return result;
}
