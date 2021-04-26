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

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/write.h"
#include "../common/merkle.h"

#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "sign_psbt.h"
#include "flows/check_merkle_tree_sorted.h"

// TODO: this is just a placeholder for now.

static void check_global_merkle_tree_sorted_result(dispatcher_context_t *dc);

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in it.
 */
void handler_sign_psbt(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dc
) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    if (p1 != 0 || p2 != 0) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        dc->send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint64_t global_map_size;
    if (!buffer_read_varint(&dc->read_buffer, &global_map_size)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (global_map_size > 252) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    state->global_map_size = (size_t)global_map_size;


    if (!buffer_read_bytes(&dc->read_buffer, state->global_keys_root, 20)
        || !buffer_read_bytes(&dc->read_buffer, state->global_values_root, 20))
    {
        PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }


    uint64_t n_inputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_inputs)
        || !buffer_read_bytes(&dc->read_buffer, state->inputs_root, 20))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_inputs > 252) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    state->n_inputs = (size_t)n_inputs;


    uint64_t n_outputs;
    if (!buffer_read_varint(&dc->read_buffer, &n_outputs)
        || !buffer_read_bytes(&dc->read_buffer, state->outputs_root, 20))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_outputs > 252) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    state->n_outputs = (size_t)n_outputs;


    call_check_merkle_tree_sorted(dc,
                                  &state->subcontext.check_merkle_tree_sorted,
                                  check_global_merkle_tree_sorted_result,
                                  state->global_keys_root,
                                  state->global_map_size);
}

static void check_global_merkle_tree_sorted_result(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    if (!state->subcontext.check_merkle_tree_sorted.result) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }


    dc->send_sw(SW_OK);
}