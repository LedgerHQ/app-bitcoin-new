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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "buffer_ext.h"

/* SDK headers */
#include "bip32.h"
#include "buffer.h"
#include "read.h"
#include "varint.h"
#include "write.h"

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
