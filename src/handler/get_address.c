/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  Y
 * ou may obtain a copy of the License at
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
#include "common/segwit_addr.h"
#include "common/write.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#define P2_PKH 0
#define P2_SH_WPKH 1
#define P2_WPKH 2

#define MAX_ADDRESS_LENGTH 74 // segwit addresses can reach 74 characters


static void ui_action_validate_address(bool accepted);

// TODO: merge global state for all commands using a union

char g_address[MAX_ADDRESS_LENGTH + 1];
size_t g_address_len;

#define MAX_ADDR_HASH_LEN 100 // TODO

// TODO: docs
// encode an address in base58check from the pubkey hash and version
static int base58_encode_address(const uint8_t *in, size_t in_len, uint32_t version, char *out, size_t out_len) {
    uint8_t tmp[4+MAX_ADDR_HASH_LEN+4]; //version + max_in_len + checksum

    if (in_len > MAX_ADDR_HASH_LEN) {
        return -1;
    }

    uint8_t version_len;
    if (version < 256) {
        tmp[0] = (uint8_t)version;
        version_len = 1;
    } else if (version < 65536) {
        write_u16_be(tmp, 0, (uint16_t)version);
        version_len = 2;
    } else {
        write_u32_be(tmp, 0, version);
        version_len = 4;
    }

    memcpy(tmp + version_len, in, in_len);
    crypto_get_checksum(tmp, version_len + in_len, tmp + version_len + in_len);
    return base58_encode(tmp, version_len + in_len + 4, out, out_len);
}


int handler_get_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context,
    void *state
) {
    if (p1 > 1 || p2 > 2) {
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

    char path_str[60] = "(root)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }


    uint32_t supported_coin_types[] = {0};
    bool is_path_suspicious = !is_path_standard(bip32_path, bip32_path_len, supported_coin_types, 1, false);

    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    keydata.prefix = 0x04;
    // derive private key according to BIP32 path
    crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);
    // generate corresponding public key
    crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
    // reset private key
    explicit_bzero(&private_key, sizeof(private_key));
    // compute compressed public key (in-place)
    crypto_get_compressed_pubkey((uint8_t *)&keydata, (uint8_t *)&keydata);

    // TODO: figure out support for uncompressed addresses! Should we support them at all?

    uint8_t pubkey_hash[20];

    switch(p2) {
        case P2_PKH:
            crypto_hash160((uint8_t *)&keydata, 33, pubkey_hash);
            g_address_len = base58_encode_address(pubkey_hash, 20, 0x00, g_address, sizeof(g_address));
            break;
        case P2_SH_WPKH: // wrapped segwit
        case P2_WPKH:    // native segwit
            {
                uint8_t script[22];
                script[0] = 0x00;
                script[1] = 0x14;
                crypto_hash160((uint8_t *)&keydata, 33, script+2);

                uint8_t script_rip[20];
                crypto_hash160((uint8_t *)&script, 22, script_rip);

                if (p2 == P2_SH_WPKH) {
                    g_address_len = base58_encode_address(script_rip, 20, 0x05, g_address, sizeof(g_address)); // TODO: support for altcoins
                } else { // P2_WPKH

                    int ret = segwit_addr_encode(
                        (char *)g_address,
                        (char *)PIC("bc"),
                        0, script + 2, 20 // TODO: generalize for other networks
                    );

                    if (ret != 1) {
                        return io_send_sw(SW_BAD_STATE); // should never happen
                    }

                    g_address_len = strlen((char *)g_address);
                }
            }
            break;
        default:
            return io_send_sw(SW_BAD_STATE); // this can never happen
    }

    g_address[g_address_len] = '\0';

    if (p1 == 1 || is_path_suspicious) {
        return ui_display_address(g_address, is_path_suspicious, ui_action_validate_address);
    } else {
        ui_action_validate_address(true);
        return 0;
    }
}

static void ui_action_validate_address(bool accepted) {
    if (accepted) {
        buffer_t response_buf = {
            .ptr = (uint8_t *)&g_address,
            .size = g_address_len,
            .offset = 0
        };
        io_send_response(&response_buf, SW_OK);
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}
