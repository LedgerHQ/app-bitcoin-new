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
#include "../common/read.h"
#include "../common/script.h"
#include "../common/segwit_addr.h"
#include "../common/wallet.h"
#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "lib/policy.h"
#include "lib/get_preimage.h"

#include "get_wallet_address.h"
#include "client_commands.h"

extern global_context_t *G_coin_config;

static void compute_address(dispatcher_context_t *dc);
static void send_response(dispatcher_context_t *dc);

void handler_get_wallet_address(dispatcher_context_t *dc, uint8_t p2) {
    (void) p2;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;

    if (!buffer_read_u8(&dc->read_buffer, &state->display_address) ||
        !buffer_read_bytes(&dc->read_buffer, state->wallet_id, 32) ||
        !buffer_read_bytes(&dc->read_buffer, state->wallet_hmac, 32)) {
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

    buffer_t serialized_wallet_policy_buf =
        buffer_create(state->serialized_wallet_policy, serialized_wallet_policy_len);

    uint8_t policy_map_descriptor[MAX_WALLET_POLICY_STR_LENGTH];
    if (0 > read_and_parse_wallet_policy(dc,
                                         &serialized_wallet_policy_buf,
                                         &state->wallet_header,
                                         policy_map_descriptor,
                                         state->wallet_policy_map_bytes,
                                         sizeof(state->wallet_policy_map_bytes))) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // the binary OR of all the hmac bytes (so == 0 iff the hmac is identically 0)
    uint8_t hmac_or = 0;
    for (int i = 0; i < 32; i++) {
        hmac_or = hmac_or | state->wallet_hmac[i];
    }

    if (hmac_or == 0) {
        // Only registered wallets are supported in HSM mode
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
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
    get_policy_wallet_id(&state->wallet_header, state->computed_wallet_id);

    if (memcmp(state->wallet_id, state->computed_wallet_id, sizeof(state->wallet_id)) != 0) {
        PRINTF("Mismatching wallet policy id\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    dc->next(compute_address);
}

// stack-intensive, split from the previous function to optimize stack usage
static void compute_address(dispatcher_context_t *dc) {
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;

    buffer_t script_buf = buffer_create(state->script, sizeof(state->script));

    int script_len = call_get_wallet_script(dc,
                                            &state->wallet_policy_map,
                                            state->wallet_header.version,
                                            state->wallet_header.keys_info_merkle_root,
                                            state->wallet_header.n_keys,
                                            state->is_change,
                                            state->address_index,
                                            &script_buf);
    if (script_len < 0) {
        PRINTF("Couldn't produce wallet script\n");
        SEND_SW(dc, SW_BAD_STATE);  // unexpected
        return;
    }

    state->address_len = get_script_address(state->script,
                                            script_len,
                                            G_coin_config,
                                            state->address,
                                            sizeof(state->address));

    if (state->address_len < 0) {
        SEND_SW(dc, SW_BAD_STATE);  // unexpected
        return;
    }

    if (state->display_address == 0) {
        dc->next(send_response);
    } else {
        ui_display_wallet_address(dc,
                                  state->is_wallet_canonical ? NULL : state->wallet_header.name,
                                  state->address,
                                  send_response);
    }
}

static void send_response(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    SEND_RESPONSE(dc, state->address, state->address_len, SW_OK);
}