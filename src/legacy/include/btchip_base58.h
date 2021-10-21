/*******************************************************************************
*   Ledger App - Bitcoin Wallet
*   (c) 2016-2019 Ledger
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
********************************************************************************/

#ifndef BTCHIP_BASE58_H

#define BTCHIP_BASE58_H

#include <stdlib.h>
#include "../../common/base58.h"

// proxies to avoid a duplicate implementation of base58 encode/decode between legacy and native app

static inline int btchip_decode_base58(const char *in, size_t length, unsigned char *out, size_t *outlen) {
    int ret = base58_decode(in, length, (uint8_t *)out, *outlen);
    if (ret >= 0) {
        *outlen = ret;
    }
    return ret;
}

static inline int btchip_encode_base58(const unsigned char *in, size_t length, unsigned char *out, size_t *outlen) {
    int ret = base58_encode(in, length, (char *)out, *outlen);
    if (ret >= 0) {
        *outlen = ret;
    }
    return ret;
}

#endif
