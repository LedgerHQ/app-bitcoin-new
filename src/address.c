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
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "os.h"
#include "cx.h"

#include "address.h"

#include "transaction/types.h"

bool address_from_pubkey(const uint8_t public_key[static 64], uint8_t *out, size_t out_len) {
    uint8_t address[32] = {0};
    cx_sha3_t keccak256;

    if (out_len < ADDRESS_LEN) {
        return false;
    }

    cx_keccak_init(&keccak256, 256);
    cx_hash((cx_hash_t *) &keccak256, CX_LAST, public_key, 64, address, sizeof(address));

    memmove(out, address + sizeof(address) - ADDRESS_LEN, ADDRESS_LEN);

    return true;
}
