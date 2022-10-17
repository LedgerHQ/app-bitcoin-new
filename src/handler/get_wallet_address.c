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

#include "boilerplate/io.h"
#include "boilerplate/sw.h"
#include "../common/base58.h"
#include "../common/bip32.h"
#include "../common/buffer.h"
#include "../common/merkle.h"
#include "../common/read.h"
#include "../common/script.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "../swap/swap_globals.h"

#include "lib/policy.h"
#include "lib/get_preimage.h"
#include "lib/get_merkle_leaf_element.h"

#include "handlers.h"
#include "client_commands.h"

void handler_get_wallet_address(dispatcher_context_t *dc, uint8_t p2) {
    (void) p2;

    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t display_address;

    uint32_t address_index;
    uint8_t is_change;

    uint8_t wallet_id[32];
    uint8_t wallet_hmac[32];

    bool is_wallet_canonical;
    int address_type;

    policy_map_wallet_header_t wallet_header;

    union {
        uint8_t bytes[MAX_WALLET_POLICY_BYTES];
        policy_node_t parsed;
    } wallet_policy_map;

    if (!buffer_read_u8(&dc->read_buffer, &display_address) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, wallet_hmac, 32)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // change
    if (!buffer_read_u8(&dc->read_buffer, &is_change)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (is_change != 0 && is_change != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // address index
    if (!buffer_read_u32(&dc->read_buffer, &address_index, BE)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    {
        uint8_t serialized_wallet_policy[MAX_WALLET_POLICY_SERIALIZED_LENGTH];

        // Fetch the serialized wallet policy from the client
        int serialized_wallet_policy_len = call_get_preimage(dc,
                                                             wallet_id,
                                                             serialized_wallet_policy,
                                                             sizeof(serialized_wallet_policy));
        if (serialized_wallet_policy_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        buffer_t serialized_wallet_policy_buf =
            buffer_create(serialized_wallet_policy, serialized_wallet_policy_len);

        uint8_t policy_map_descriptor[MAX_DESCRIPTOR_TEMPLATE_LENGTH];
        if (0 > read_and_parse_wallet_policy(dc,
                                             &serialized_wallet_policy_buf,
                                             &wallet_header,
                                             policy_map_descriptor,
                                             wallet_policy_map.bytes,
                                             sizeof(wallet_policy_map.bytes))) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    uint8_t hmac_or = 0;
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | wallet_hmac[i];
    }

    if (hmac_or == 0) {
        // No hmac, verify that the policy is a canonical one that is allowed by default
        address_type = get_policy_address_type(&wallet_policy_map.parsed);
        if (address_type == -1) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        if (wallet_header.n_keys != 1) {
            PRINTF("Standard wallets must have exactly 1 key\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // we check if the key is indeed internal
        uint32_t master_key_fingerprint = crypto_get_master_key_fingerprint();

        uint8_t key_info_str[MAX_POLICY_KEY_INFO_LEN];
        int key_info_len = call_get_merkle_leaf_element(dc,
                                                        wallet_header.keys_info_merkle_root,
                                                        wallet_header.n_keys,
                                                        0,  // only one key
                                                        key_info_str,
                                                        sizeof(key_info_str));
        if (key_info_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // Make a sub-buffer for the pubkey info
        buffer_t key_info_buffer = buffer_create(key_info_str, key_info_len);

        policy_map_key_info_t key_info;
        if (parse_policy_map_key_info(&key_info_buffer, &key_info, wallet_header.version) == -1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        if (read_u32_be(key_info.master_key_fingerprint, 0) != master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // generate pubkey and check if it matches
        char pubkey_derived[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
        int serialized_pubkey_len =
            get_serialized_extended_pubkey_at_path(key_info.master_key_derivation,
                                                   key_info.master_key_derivation_len,
                                                   BIP32_PUBKEY_VERSION,
                                                   pubkey_derived,
                                                   NULL);
        if (serialized_pubkey_len == -1) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        if (strncmp(key_info.ext_pubkey, pubkey_derived, MAX_SERIALIZED_PUBKEY_LENGTH) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        // check if derivation path is indeed standard

        // Based on the address type, we set the expected bip44 purpose for this canonical wallet
        int bip44_purpose = get_bip44_purpose(address_type);

        if (key_info.master_key_derivation_len != 3) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint32_t coin_types[2] = {BIP44_COIN_TYPE, BIP44_COIN_TYPE_2};

        uint32_t bip32_path[5];
        for (int i = 0; i < 3; i++) {
            bip32_path[i] = key_info.master_key_derivation[i];
        }
        bip32_path[3] = is_change ? 1 : 0;
        bip32_path[4] = address_index;

        if (!is_address_path_standard(bip32_path, 5, bip44_purpose, coin_types, 2, -1)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        is_wallet_canonical = true;
    } else {
        // Verify hmac

        if (!check_wallet_hmac(wallet_id, wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        is_wallet_canonical = false;
    }

    // Swap feature: check that wallet is canonical
    if (G_swap_state.called_from_swap && !is_wallet_canonical) {
        PRINTF("Must be a canonical wallet for swap feature\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    {
        uint8_t computed_wallet_id[32];
        // Compute the wallet id (sha256 of the serialization)
        get_policy_wallet_id(&wallet_header, computed_wallet_id);

        if (memcmp(wallet_id, computed_wallet_id, sizeof(wallet_id)) != 0) {
            PRINTF("Mismatching wallet policy id\n");
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
    }

    {
        uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        buffer_t script_buf = buffer_create(script, sizeof(script));

        int script_len = call_get_wallet_script(dc,
                                                &wallet_policy_map.parsed,
                                                wallet_header.version,
                                                wallet_header.keys_info_merkle_root,
                                                wallet_header.n_keys,
                                                is_change,
                                                address_index,
                                                &script_buf);
        if (script_len < 0) {
            PRINTF("Couldn't produce wallet script\n");
            SEND_SW(dc, SW_BAD_STATE);  // unexpected
            return;
        }

        int address_len;
        char address[MAX_ADDRESS_LENGTH_STR + 1];  // null-terminated string

        address_len = get_script_address(script, script_len, address, sizeof(address));

        if (address_len < 0) {
            SEND_SW(dc, SW_BAD_STATE);  // unexpected
            return;
        }

        if (display_address != 0) {
            if (!ui_display_wallet_address(dc,
                                           is_wallet_canonical ? NULL : wallet_header.name,
                                           address)) {
                SEND_SW(dc, SW_DENY);
                return;
            }
        }

        SEND_RESPONSE(dc, address, address_len, SW_OK);
    }
}
