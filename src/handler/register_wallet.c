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

#include "os.h"
#include "cx.h"

#include "boilerplate/io.h"
#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"
#include "register_wallet.h"

static void ui_action_validate_header(dispatcher_context_t *dc, bool accept);
static void request_next_cosigner(dispatcher_context_t *dc);
static void read_next_cosigner(dispatcher_context_t *dc);
static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept);


/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in it.
 */
void handler_register_wallet(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (p1 != 0 || p2 != 0) {
        io_send_sw(SW_WRONG_P1P2);
        return;
    }
    if (lc < 3) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        io_send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t wallet_type;
    buffer_read_u8(&dispatcher_context->read_buffer, &wallet_type);

    if (wallet_type != WALLET_TYPE_MULTISIG) {
        io_send_sw(SW_INCORRECT_DATA); // TODO: should add a field for "unsupported"? It might mean the app is outdated.
        return;
    }

    uint8_t wallet_name_len;
    buffer_read_u8(&dispatcher_context->read_buffer, &wallet_name_len);

    if (wallet_name_len > MAX_WALLET_NAME_LENGTH) {
        io_send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (lc != 1 + 1 + wallet_name_len + 1 + 1) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    for (int i = 0; i < wallet_name_len; i++) {
        buffer_read_u8(&dispatcher_context->read_buffer, &state->wallet_name[i]);
    }
    state->wallet_name[wallet_name_len] = '\0';

    buffer_read_u8(&dispatcher_context->read_buffer, &state->threshold);
    buffer_read_u8(&dispatcher_context->read_buffer, &state->n_keys);

    if (state->threshold == 0 || state->n_keys == 0 || state->n_keys > 15 || state->threshold > state->n_keys) {
        io_send_sw(SW_INCORRECT_DATA);
        return;
    }

    cx_sha256_init(&state->wallet_hash_context);

    crypto_hash_update(&state->wallet_hash_context.header, &wallet_type, 1);
    crypto_hash_update(&state->wallet_hash_context.header, &wallet_name_len, 1);
    crypto_hash_update(&state->wallet_hash_context.header, &state->wallet_name, wallet_name_len);
    crypto_hash_update(&state->wallet_hash_context.header, &state->threshold, 1);
    crypto_hash_update(&state->wallet_hash_context.header, &state->n_keys, 1);

    state->next_pubkey_index = 0;
    ui_display_multisig_header(dispatcher_context,
                               (char *)state->wallet_name,
                               state->threshold,
                               state->n_keys,
                               ui_action_validate_header);
}

/**
 * Abort if the user rejected the wallet header, otherwise start processing the pubkeys.
 */
static void ui_action_validate_header(dispatcher_context_t *dc, bool accept) {
    if (!accept) {
        io_send_sw(SW_DENY);
        ui_menu_main();
    } else {
        request_next_cosigner(dc);
    }
}

/**
 * Interrupts the command, asking the host for the next pubkey.
 */
static void request_next_cosigner(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    dc->continuation = read_next_cosigner;

    uint8_t req[] = { CCMD_GET_COSIGNER_PUBKEY, state->next_pubkey_index};

    io_send_response(req, 2, SW_INTERRUPTED_EXECUTION);
}

/**
 * Receives the next xpub, accumulates it in the hash context, then asks the user to validate it.
 */
static void read_next_cosigner(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    uint8_t pubkey_len;
    uint8_t pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];

    if (!buffer_read_u8(&dc->read_buffer, &pubkey_len)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (pubkey_len > MAX_SERIALIZED_PUBKEY_LENGTH) {
        io_send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_move(&dc->read_buffer, pubkey, pubkey_len)) {
        io_send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    pubkey[pubkey_len] = '\0';

    // TODO: it would be sensible to validate the pubkey (at least syntactically + validate checksum)
    //       Currently we are showing to the user whichever string is passed by the host.

    crypto_hash_update(&state->wallet_hash_context.header, &pubkey_len, 1);
    crypto_hash_update(&state->wallet_hash_context.header, &pubkey, pubkey_len);

    ui_display_multisig_cosigner_pubkey(dc,
                                        (char *)pubkey,
                                        1 + state->next_pubkey_index, // 1-indexed for the UI
                                        state->n_keys,
                                        ui_action_validate_cosigner);
}

/**
 * Aborts if the user rejected the pubkey; if more xpubs are to be read, goes back to request_next_cosigner.
 * Otherwise, finalizes the hash, and returns the sha256 digest and the signature as the final response.
 */
static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (!accept) {
        io_send_sw(SW_DENY);
        ui_menu_main();
    } else {
        ++state->next_pubkey_index;
        if (state->next_pubkey_index < state->n_keys) {
            request_next_cosigner(dc);
        } else {

            // TODO: validate wallet.
            // - is one of the xpubs ours? (exactly one? How to check?)

            struct {
                uint8_t wallet_hash[32];
                uint8_t signature_len;
                uint8_t signature[MAX_DER_SIG_LEN]; // the actual response might be shorter
            } response;

            crypto_hash_digest(&state->wallet_hash_context.header, response.wallet_hash, 32);

            // sign hash and produce response
            int signature_len = crypto_sign_sha256_hash(response.wallet_hash, response.signature);
            response.signature_len = (uint8_t)signature_len;

            io_send_response(&response, 32 + 1 + signature_len, SW_OK);

            ui_menu_main();
        }
    }
}