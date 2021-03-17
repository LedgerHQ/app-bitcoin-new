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
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);

int handler_get_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    get_address_state_t *state = (get_address_state_t *)&G_command_state;

    if (p1 > 1) {
        return io_send_sw(SW_WRONG_P1P2);
    }
    if (p2 != ADDRESS_TYPE_PKH && p2 != ADDRESS_TYPE_SH_WPKH && p2 != ADDRESS_TYPE_WPKH) {
        return io_send_sw(SW_WRONG_P1P2);
    }

    uint32_t purpose; // the valid purpose depends on the requested address type
    switch(p2) {
        case ADDRESS_TYPE_PKH:     //legacy
            purpose = 44;
            break;
        case ADDRESS_TYPE_SH_WPKH: // wrapped segwit
            purpose = 49;
            break;
        case ADDRESS_TYPE_WPKH:    // native segwit
            purpose = 84;
            break;
        default:
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

    if (bip32_path_len > MAX_BIP32_PATH_STEPS) {
        return io_send_sw(SW_INCORRECT_DATA);
    }

    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    if (!buffer_read_bip32_path(&dispatcher_context->read_buffer, bip32_path, bip32_path_len)) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    char path_str[60] = "(root)";
    if (bip32_path_len > 0) {
        bip32_path_format(bip32_path, bip32_path_len, path_str, sizeof(path_str));
    }

    uint32_t supported_coin_types[] = {0};
    bool is_path_suspicious = !is_address_path_standard(bip32_path,
                                                        bip32_path_len, 
                                                        purpose,
                                                        supported_coin_types,
                                                        1,
                                                        false);

    int ret = get_address_at_path(bip32_path, bip32_path_len, p2, state->address);
    if (ret < 0) {
        return io_send_sw(SW_BAD_STATE);
    }
    state->address_len = (size_t)ret;

    if (p1 == 1 || is_path_suspicious) {
        return ui_display_address(dispatcher_context, state->address, is_path_suspicious, ui_action_validate_address);
    } else {
        ui_action_validate_address(dispatcher_context, true);
        return 0;
    }
}

static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_address_state_t *state = (get_address_state_t *)&G_command_state;

    if (accepted) {
        io_send_response(state->address, state->address_len, SW_OK);
    } else {
        io_send_sw(SW_DENY);
    }

    ui_menu_main();
}
