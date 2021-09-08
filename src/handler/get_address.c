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

#include <stdint.h>

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../common/segwit_addr.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

extern global_context_t *G_coin_config;

static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);

static int get_address_at_path(const uint32_t bip32_path[],
                               uint8_t bip32_path_len,
                               uint8_t address_type,
                               char out[static MAX_ADDRESS_LENGTH_STR + 1]);

void handler_get_address(dispatcher_context_t *dc) {
    get_address_state_t *state = (get_address_state_t *) &G_command_state;

    uint8_t display, address_type;
    if (!buffer_read_u8(&dc->read_buffer, &display) ||
        !buffer_read_u8(&dc->read_buffer, &address_type)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (display != 0 && display != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // TODO: handle ADDRESS_TYPE_TAPROOT if this APDU is not removed
    if (address_type != ADDRESS_TYPE_LEGACY && address_type != ADDRESS_TYPE_WIT &&
        address_type != ADDRESS_TYPE_SH_WIT) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint32_t purpose;  // the valid purpose depends on the requested address type
    switch (address_type) {
        case ADDRESS_TYPE_LEGACY:  // legacy
            purpose = 44;
            break;
        case ADDRESS_TYPE_WIT:  // native segwit
            purpose = 84;
            break;
        case ADDRESS_TYPE_SH_WIT:  // wrapped segwit
            purpose = 49;
            break;
        default:
            SEND_SW(dc, SW_BAD_STATE);  // cannot happen
            return;
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t bip32_path_len;
    buffer_read_u8(&dc->read_buffer, &bip32_path_len);

    if (bip32_path_len > MAX_BIP32_PATH_STEPS) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    if (!buffer_read_bip32_path(&dc->read_buffer, bip32_path, bip32_path_len)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    char path_str[60] = "(root)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }

    uint32_t coin_types[2] = {G_coin_config->bip44_coin_type, G_coin_config->bip44_coin_type2};
    bool is_path_suspicious =
        !is_address_path_standard(bip32_path, bip32_path_len, purpose, coin_types, 2, false);

    int ret = get_address_at_path(bip32_path, bip32_path_len, address_type, state->address);
    if (ret < 0) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    state->address_len = (size_t) ret;

    if (display == 1 || is_path_suspicious) {
        dc->pause();
        ui_display_address(dc,
                           state->address,
                           is_path_suspicious,
                           path_str,
                           ui_action_validate_address);
    } else {
        SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
    }
}

static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_address_state_t *state = (get_address_state_t *) &G_command_state;

    if (accepted) {
        SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
    } else {
        SEND_SW(dc, SW_DENY);
    }

    dc->run();
}

// TODO: refactor: split the pubkey generation for the BIP32 path from the address generation

/**
 * Computes an address for one of the supported types at a given BIP32 derivation path.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit integer input buffer.
 * @param[in]  bip32_path_len
 *   Maximum number of BIP32 paths in the input buffer.
 * @param[in]  address_type
 *   One of ADDRESS_TYPE_LEGACY, ADDRESS_TYPE_WIT, ADDRESS_TYPE_SH_WIT.
 * @param[out]  out
 *   Pointer to the output array, that must be long enough to contain the result.
 *
 * @return the length of the computed address on success, -1 on failure.
 */
static int get_address_at_path(const uint32_t bip32_path[],
                               uint8_t bip32_path_len,
                               uint8_t address_type,
                               char out[static MAX_ADDRESS_LENGTH_STR + 1]) {
    cx_ecfp_private_key_t private_key = {0};
    cx_ecfp_public_key_t public_key;

    struct {
        uint8_t prefix;
        uint8_t raw_public_key[64];
        uint8_t chain_code[32];
    } keydata;

    keydata.prefix = 0x04;

    BEGIN_TRY {
        TRY {
            // derive private key according to BIP32 path
            crypto_derive_private_key(&private_key, keydata.chain_code, bip32_path, bip32_path_len);
            // generate corresponding public key
            crypto_init_public_key(&private_key, &public_key, keydata.raw_public_key);
        }
        FINALLY {
            // reset private key
            explicit_bzero(&private_key, sizeof(private_key));
        }
    }
    END_TRY;

    // compute compressed public key (in-place)
    crypto_get_compressed_pubkey((uint8_t *) &keydata, (uint8_t *) &keydata);

    uint8_t pubkey_hash[20];
    size_t address_len;

    switch (address_type) {
        case ADDRESS_TYPE_LEGACY:
            crypto_hash160((uint8_t *) &keydata, 33, pubkey_hash);
            address_len = base58_encode_address(pubkey_hash,
                                                G_coin_config->p2pkh_version,
                                                out,
                                                MAX_ADDRESS_LENGTH_STR);
            break;
        case ADDRESS_TYPE_WIT:     // native segwit
        case ADDRESS_TYPE_SH_WIT:  // wrapped segwit
        {
            uint8_t script[22];
            script[0] = 0x00;  // OP_0
            script[1] = 0x14;  // PUSH 20 bytes
            crypto_hash160((uint8_t *) &keydata, 33, script + 2);

            uint8_t script_rip[20];
            crypto_hash160((uint8_t *) &script, 22, script_rip);

            if (address_type == ADDRESS_TYPE_SH_WIT) {
                address_len = base58_encode_address(script_rip,
                                                    G_coin_config->p2sh_version,
                                                    out,
                                                    MAX_ADDRESS_LENGTH_STR);
            } else {  // ADDRESS_TYPE_WIT
                int ret =
                    segwit_addr_encode(out, G_coin_config->native_segwit_prefix, 0, script + 2, 20);

                if (ret != 1) {
                    return -1;  // should never happen
                }

                address_len = strlen(out);
            }
        } break;
        default:
            return -1;  // this can never happen
    }

    out[address_len] = '\0';
    return address_len;
}
