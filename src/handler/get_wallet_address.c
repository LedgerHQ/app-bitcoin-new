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

#include "get_wallet_address.h"
#include "client_commands.h"


extern global_context_t G_context;

static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);

void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dc
) {
    (void)lc;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;
    if (p1 != 0 && p1 != 1) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    if (p2 != 0) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    state->display_address = p1;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        dc->send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t sig_len;
    uint8_t sig[MAX_DER_SIG_LEN];
    if (!buffer_read_u8(&dc->read_buffer, &sig_len) ||
        !buffer_read_bytes(&dc->read_buffer, sig, sig_len)
    ) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Verify signature
    if (!crypto_verify_sha256_hash(wallet_id, sig, sig_len)) {
        dc->send_sw(SW_SIGNATURE_FAIL);
        return;
    }

    if ((read_policy_map_wallet(&dc->read_buffer, &state->wallet_header)) < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    buffer_t policy_map_buffer = buffer_create(&state->wallet_header.policy_map, state->wallet_header.policy_map_len);


    PRINTF("%s\n", state->wallet_header.policy_map);
    int tmp;
    if ((tmp = parse_policy_map(&policy_map_buffer, state->policy_map_bytes, sizeof(state->policy_map_bytes)) < 0)) {
        PRINTF("Failed parsing policy map\n");
        PRINTF("%d\n", tmp);
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // change
    if (!buffer_read_u8(&dc->read_buffer, &state->is_change)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (state->is_change != 0 && state->is_change != 1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // address index
    if (!buffer_read_u32(&dc->read_buffer, &state->address_index, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Compute the wallet id (sha256 of the serialization)
    uint8_t computed_wallet_id[32];
    get_policy_wallet_id(&state->wallet_header, computed_wallet_id);

    if (memcmp(wallet_id, computed_wallet_id, sizeof(wallet_id)) != 0) {
        dc->send_sw(SW_INCORRECT_DATA); // TODO: more specific error code
        return;
    }

    int res = call_get_wallet_address(dc,
                                      &state->policy_map,
                                      state->wallet_header.keys_info_merkle_root,
                                      state->wallet_header.n_keys,
                                      state->is_change,
                                      state->address_index,
                                      state->address,
                                      sizeof(state->address));
    if (res < 0) {
        PRINTF("Response to get_wallet_address: %d\n", res);
        dc->send_sw(SW_BAD_STATE); // unexpected
        return;
    }
    state->address_len = res;

    if (state->display_address == 0) {
        dc->send_response(state->address, state->address_len, SW_OK);
    } else {
        dc->pause();
        ui_display_wallet_address(dc, state->wallet_header.name, state->address, ui_action_validate_address);
    }
}


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    if (accepted) {
        dc->send_response(state->address, state->address_len, SW_OK);
    } else {
        dc->send_sw(SW_DENY);
    }

    dc->run();
}
