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
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"
#include "register_wallet.h"

#include "cx.h"

static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept);

int handler_register_wallet(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (p1 != 0 || p2 != 0) {
        return io_send_sw(SW_WRONG_P1P2);
    }
    if (lc < 3) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        return io_send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    uint8_t wallet_type;
    buffer_read_u8(&dispatcher_context->read_buffer, &wallet_type);

    if (wallet_type != WALLET_TYPE_MULTISIG) {
        return io_send_sw(SW_INCORRECT_DATA); // TODO: should add a field for "unsopported"? It might mean the app is outdated.
    }

    uint8_t wallet_name_len;
    buffer_read_u8(&dispatcher_context->read_buffer, &wallet_name_len);

    if (wallet_name_len > MAX_WALLET_NAME_LENGTH) {
        return io_send_sw(SW_INCORRECT_DATA);
    }

    if (lc != 1 + 1 + wallet_name_len + 1 + 1) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    for (int i = 0; i < wallet_name_len; i++) {
        buffer_read_u8(&dispatcher_context->read_buffer, &state->wallet_name[i]);
    }
    state->wallet_name[wallet_name_len] = '\0';

    buffer_read_u8(&dispatcher_context->read_buffer, &state->threshold);
    buffer_read_u8(&dispatcher_context->read_buffer, &state->n_keys);

    cx_sha256_init(&state->wallet_hash_context);

    // TODO: read pubkeys

    uint8_t wallet_hash[32];
    cx_hash(&state->wallet_hash_context.header, 0, (unsigned char *)&wallet_type, 1, NULL, 0);
    cx_hash(&state->wallet_hash_context.header, 0, (unsigned char *)&wallet_name_len, 1, NULL, 0);
    cx_hash(&state->wallet_hash_context.header, 0, (unsigned char *)&state->wallet_name, wallet_name_len, NULL, 0);
    cx_hash(&state->wallet_hash_context.header, 0, (unsigned char *)&state->threshold, 1, NULL, 0);
    cx_hash(&state->wallet_hash_context.header, 0, (unsigned char *)&state->n_keys, 1, wallet_hash, 32);

    state->next_pubkey_index = 0;
    return ui_display_multisig_header(dispatcher_context,
                                      (char *)state->wallet_name,
                                      state->threshold,
                                      state->n_keys,
                                      ui_action_validate_cosigner);
}

static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (!accept) {
        io_send_sw(SW_DENY);
    } else {
        if (state->next_pubkey_index < state->n_keys) {
            // TODO
            char pubkey[] = "xpubetcetcjlkjgslkfdjlksjdf;lkdsf;lsdk;lfdsk;lf";
            ++state->next_pubkey_index;
            ui_display_multisig_cosigner_pubkey(dc, pubkey, state->next_pubkey_index, state->n_keys, ui_action_validate_cosigner);
            return;
        } else {
            //TODO: all good, send signature back
        }
    }

    ui_menu_main();
}
