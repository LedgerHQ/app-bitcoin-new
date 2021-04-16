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

#include "boilerplate/dispatcher.h"
#include "boilerplate/sw.h"
#include "../commands.h"
#include "../constants.h"
#include "../types.h"
#include "client_commands.h"

static void processor_get_sum_of_squares(dispatcher_context_t *dispatcher_context);
static void get_next_square(dispatcher_context_t *dispatcher_context);
static void receive_next_square(dispatcher_context_t *dispatcher_context);


void handler_get_sum_of_squares(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state;
    uint8_t n;

    if (p1 != 0 || p2 != 0) {
        dispatcher_context->send_sw(SW_WRONG_P1P2);
        return;
    }
    if (lc != 1) {
        dispatcher_context->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    buffer_read_u8(&dispatcher_context->read_buffer, &n);

    state->n = n;
    state->i = 1;
    state->sum = 0;

    dispatcher_context->next(processor_get_sum_of_squares);
}

static void processor_get_sum_of_squares(dispatcher_context_t *dispatcher_context) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state;

    if (state->i <= state->n) {
        dispatcher_context->next(get_next_square);
    } else {
        dispatcher_context->send_response(&state->sum, 4, SW_OK);
    }
}

static void get_next_square(dispatcher_context_t *dispatcher_context) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state;

    // prepare the EXT_GET_SQUARE response for the user
    uint8_t req[] = { CCMD_GET_SQUARE, state->i };
    dispatcher_context->send_response(req, 2, SW_INTERRUPTED_EXECUTION);

    dispatcher_context->next(receive_next_square);
}

static void receive_next_square(dispatcher_context_t *dispatcher_context) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state;

    uint32_t result;
    if (!buffer_read_u32(&dispatcher_context->read_buffer, &result, BE)) {
        dispatcher_context->send_sw(SW_WRONG_DATA_LENGTH);
    } else {
        state->sum += result;
        ++state->i;
        dispatcher_context->next(processor_get_sum_of_squares);
    }
}
