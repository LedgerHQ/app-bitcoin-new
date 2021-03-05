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

#include <stdint.h>  // uint*_t

#include "boilerplate/io.h"
#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "common/base58.h"
#include "common/buffer.h"
#include "common/read.h"
#include "common/write.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "client_commands.h"

static struct {
    uint8_t version[4];
    uint8_t depth;
    uint8_t parent_fingerprint[4];
    uint8_t child_number[4];
    uint8_t chain_code[32];
    uint8_t compressed_pubkey[33];  // SEC1 compressed public key
    uint8_t checksum[4];
} g_ext_pubkey;

char g_serialized_pubkey_str[113];


static void ui_action_validate_pubkey(bool choice);


int handler_get_pubkey(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context,
    void *state
) {
    if (p1 > 1 || p2 != 0) {
        return io_send_sw(SW_WRONG_P1P2);
    }
    if (lc < 1) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        return io_send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    uint8_t bip32_path_len;
    buffer_read_u8(&dispatcher_context->read_buffer, &bip32_path_len);

    if (bip32_path_len > MAX_BIP32_PATH) {
        return io_send_sw(SW_INCORRECT_DATA);
    }

    uint32_t bip32_path[MAX_BIP32_PATH];
    if (!buffer_read_bip32_path(&dispatcher_context->read_buffer, bip32_path, bip32_path_len)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    // TODO: should we allow arbitrary paths? Should we alert the user for non-standard paths?

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    // find parent key's fingerprint and child number
    uint32_t parent_fingerprint = 0;
    uint32_t child_number = 0;
    if (bip32_path_len > 0) {
        // here we reuse the storage for the parent keys that we will later use
        // for the response, in order to save memory

        keydata.prefix  = 0x04; // uncompressed public keys always start with 04
        // derive private key according to BIP32 path
        crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len - 1);
        // generate corresponding public key
        crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
        // reset private key (we could skip as we overwrite it later; but it won't hurt)
        explicit_bzero(&private_key, sizeof(private_key));

        // compute compressed public key (in-place)
        crypto_get_compressed_pubkey((uint8_t *)&keydata, (uint8_t *)&keydata);
        uint8_t parent_key_hash[20];
        crypto_hash160((uint8_t *)&keydata, 33, parent_key_hash);
        parent_fingerprint = read_u32_be(parent_key_hash, 0);
        child_number = bip32_path[bip32_path_len - 1];
    }

    write_u32_be(g_ext_pubkey.version, 0, 0x0488B21E); // TODO: generalize to all networks
    g_ext_pubkey.depth = bip32_path_len;
    write_u32_be(g_ext_pubkey.parent_fingerprint, 0, parent_fingerprint);
    write_u32_be(g_ext_pubkey.child_number, 0, child_number);

    // extkey = version + depth + fpr + child + chainCode + publicKey

    keydata.prefix  = 0x04; // uncompressed public keys always start with 04
    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);
    // generate corresponding public key
    crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
    // reset private key
    explicit_bzero(&private_key, sizeof(private_key));
    // compute compressed public key (in-place)
    crypto_get_compressed_pubkey((uint8_t *)&keydata, (uint8_t *)&keydata);

    memmove(g_ext_pubkey.chain_code, keydata.chain_code, 32);
    memmove(g_ext_pubkey.compressed_pubkey, (uint8_t *)&keydata, 33);

    crypto_get_checksum((uint8_t *)&g_ext_pubkey, 78, g_ext_pubkey.checksum);

    char g_serialized_pubkey_str[113];
    int serialized_pubkey_len = base58_encode((uint8_t *)&g_ext_pubkey, 78 + 4, g_serialized_pubkey_str, 112);
    g_serialized_pubkey_str[serialized_pubkey_len] = '\0';

    char path_str[60] = "Master key";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }
    // TODO: handle if the path is too long to fit in path_str

    if (p1 == 1) {
        return ui_display_pubkey(path_str, g_serialized_pubkey_str, ui_action_validate_pubkey);
    } else {
        buffer_t response_buf = {
            .ptr = (uint8_t *)&g_serialized_pubkey_str,
            .size = strlen(g_serialized_pubkey_str),
            .offset = 0
        };
        io_send_response(&response_buf, SW_OK);
    }
}

static void ui_action_validate_pubkey(bool choice) {
    if (choice) {
        buffer_t response_buf = {
            .ptr = (uint8_t *)&g_serialized_pubkey_str,
            .size = strlen(g_serialized_pubkey_str),
            .offset = 0
        };
        io_send_response(&response_buf, SW_OK);
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}
