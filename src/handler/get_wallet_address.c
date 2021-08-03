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
#include "../common/buffer.h"
#include "../common/merkle.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "lib/policy.h"
#include "lib/get_preimage.h"

#include "get_wallet_address.h"
#include "client_commands.h"


extern global_context_t G_context;

static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);


void handler_get_wallet_address(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    if (   !buffer_read_u8(&dc->read_buffer, &state->display_address)
        || !buffer_read_bytes(&dc->read_buffer, state->wallet_id, 32)
        || !buffer_read_bytes(&dc->read_buffer, state->wallet_hmac, 32))
    {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // change
    if (!buffer_read_u8(&dc->read_buffer, &state->is_change)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (state->is_change != 0 && state->is_change != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // address index
    if (!buffer_read_u32(&dc->read_buffer, &state->address_index, BE)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    // Fetch the serialized wallet policy from the client
    int serialized_wallet_policy_len = call_get_preimage(dc,
                                                         state->wallet_id,
                                                         state->serialized_wallet_policy,
                                                         sizeof(state->serialized_wallet_policy));
    if (serialized_wallet_policy_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    policy_map_wallet_header_t wallet_header;
    buffer_t serialized_wallet_policy_buf = buffer_create(state->serialized_wallet_policy, serialized_wallet_policy_len);
    if ((read_policy_map_wallet(&serialized_wallet_policy_buf, &wallet_header)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(state->wallet_header_keys_info_merkle_root, wallet_header.keys_info_merkle_root, sizeof(wallet_header.keys_info_merkle_root));
    state->wallet_header_n_keys = wallet_header.n_keys;

    buffer_t policy_map_buffer = buffer_create(&wallet_header.policy_map, wallet_header.policy_map_len);

    if (parse_policy_map(&policy_map_buffer, state->wallet_policy_map_bytes, sizeof(state->wallet_policy_map_bytes)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint8_t hmac_or = 0; // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | state->wallet_hmac[i];
    }

    if (hmac_or == 0) {
        // No hmac, verify that the policy is a canonical one that is allowed by default
        state->address_type = get_policy_address_type(&state->wallet_policy_map);
        if (state->address_type == -1) {
            PRINTF("Non-standard policy, and no hmac provided\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        state->is_wallet_canonical = true;
    } else {
        // Verify hmac

        if (!check_wallet_hmac(state->wallet_id, state->wallet_hmac)) {
            PRINTF("Incorrect hmac\n");
            SEND_SW(dc, SW_SIGNATURE_FAIL);
            return;
        }

        state->is_wallet_canonical = false;
    }

    // Compute the wallet id (sha256 of the serialization)
    uint8_t computed_wallet_id[32];
    get_policy_wallet_id(&wallet_header, computed_wallet_id);

    if (memcmp(state->wallet_id, computed_wallet_id, sizeof(state->wallet_id)) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA); // TODO: more specific error code
        return;
    }

    // TODO: for canonical wallets, we should check that there is only one key and its path is also canonical,
    //       (matching the expected path based on the address type provided above), account index not too large.

    uint8_t script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    buffer_t script_buf = buffer_create(script, sizeof(script));

    int script_len = call_get_wallet_script(dc,
                                            &state->wallet_policy_map,
                                            state->wallet_header_keys_info_merkle_root,
                                            state->wallet_header_n_keys,
                                            state->is_change,
                                            state->address_index,
                                            &script_buf,
                                            NULL);
    if (script_len < 0) {
        SEND_SW(dc, SW_BAD_STATE); // unexpected
        return;
    }

    state->address_len = get_script_address(script, script_len, G_context, state->address, sizeof(state->address));

    if (state->address_len < 0) {
        SEND_SW(dc, SW_BAD_STATE); // unexpected
        return;
    }

    if (state->display_address == 0) {
        SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
    } else {
        dc->pause();
        ui_display_wallet_address(dc,
                                  state->is_wallet_canonical ? NULL : wallet_header.name,
                                  state->address,
                                  ui_action_validate_address);
    }
}


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (accepted) {
        SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
    } else {
        SEND_SW(dc, SW_DENY);
    }

    dc->run();
}
