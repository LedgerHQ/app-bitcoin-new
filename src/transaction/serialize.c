/*****************************************************************************
 *   Ledger App Boilerplate.
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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memmove

#include "serialize.h"
#include "../common/write.h"
#include "../common/varint.h"

int transaction_serialize(const transaction_t *tx, uint8_t *out, size_t out_len) {
    size_t offset = 0;

    if (8 + ADDRESS_LEN + 8 + varint_size(tx->memo_len) + tx->memo_len > out_len) {
        return -1;
    }

    // nonce
    write_u64_be(out, offset, tx->nonce);
    offset += 8;

    // to
    memmove(out + offset, tx->to, ADDRESS_LEN);
    offset += ADDRESS_LEN;

    // value
    write_u64_be(out, offset, tx->value);
    offset += 8;

    // memo length
    int varint_len = varint_write(out, offset, tx->memo_len);
    if (varint_len < 0) {
        return -1;
    }
    offset += varint_len;

    // memo
    memmove(out + offset, tx->memo, tx->memo_len);
    offset += tx->memo_len;

    return (int) offset;
}
