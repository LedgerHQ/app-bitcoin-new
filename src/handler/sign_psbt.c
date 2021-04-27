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


// TODO: this is just a placeholder for now.

static void request_next_input_map(dispatcher_context_t *dc);
static void receive_next_input_map(dispatcher_context_t *dc);

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

    if (!buffer_read_varint(&dc->read_buffer, &state->global_map.size)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (state->global_map.size > 252) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }


    if (!buffer_read_bytes(&dc->read_buffer, state->global_map.keys_root, 20)
        || !buffer_read_bytes(&dc->read_buffer, state->global_map.values_root, 20))
    {
        LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);
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

    state->cur_input_index = 0;

    call_check_merkle_tree_sorted(dc,
                                  &state->subcontext.check_merkle_tree_sorted,
                                  request_next_input_map,
                                  state->global_map.keys_root,
                                  (size_t)state->global_map.size);
}


static void request_next_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // TODO: get merkleized input map
    call_get_merkleized_map(dc,
                            &state->subcontext.get_merkleized_map,
                            receive_next_input_map,
                            state->inputs_root,
                            state->n_inputs,
                            state->cur_input_index,
                            &state->cur_input_map);
}

static void receive_next_input_map(dispatcher_context_t *dc) {
    sign_psbt_state_t *state = (sign_psbt_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    
}