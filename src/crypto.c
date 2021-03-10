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

#include "os.h"

#include "crypto.h"

// TODO: missing unit tests
int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len) {
    uint8_t raw_private_key[32] = {0};

    // TODO: disabled exception handling, as it breaks with CMocha. Once the sdk is updated,
    //       there will be versions of the cx.h functions that do not throw exceptions.
    //       NOTE: the current version is insecure as it might not wipe the private key after usage!

    // BEGIN_TRY {
    //     TRY {
            // derive the seed with bip32_path
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       bip32_path,
                                       bip32_path_len,
                                       raw_private_key,
                                       chain_code);
            // new private_key from raw
            cx_ecfp_init_private_key(CX_CURVE_256K1,
                                     raw_private_key,
                                     sizeof(raw_private_key),
                                     private_key);
        // }
        // CATCH_OTHER(e) {
        //     THROW(e);
        // }
        // FINALLY {
            explicit_bzero(&raw_private_key, sizeof(raw_private_key));
    //     }
    // }
    // END_TRY;

    return 0;
}


// TODO: missing unit tests
int crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                           cx_ecfp_public_key_t *public_key,
                           uint8_t raw_public_key[static 64]) {
    // generate corresponding public key
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);

    memmove(raw_public_key, public_key->W + 1, 64);

    return 0;
}


// TODO: missing unit tests
void crypto_hash160(uint8_t *in, uint16_t inlen, uint8_t out[static 20]) {
    cx_ripemd160_t riprip;
    uint8_t buffer[32];
    cx_hash_sha256(in, inlen, buffer, 32);
    cx_ripemd160_init(&riprip);
    cx_hash(&riprip.header, CX_LAST, buffer, 32, out, 20);
}


int crypto_get_compressed_pubkey(uint8_t uncompressed_key[static 65], uint8_t out[static 33]) {
    if (uncompressed_key[0] != 0x04) {
        return -1;
    }
    out[0] = (uncompressed_key[64] % 2 == 1) ? 0x03 : 0x02;
    memmove(out + 1, uncompressed_key + 1, 32);
    return 0;
}


// TODO: missing unit tests
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]) {
    uint8_t buffer[32];
    cx_hash_sha256(in, in_len, buffer, 32);
    cx_hash_sha256(buffer, 32, buffer, 32);
    os_memmove(out, buffer, 4);
}