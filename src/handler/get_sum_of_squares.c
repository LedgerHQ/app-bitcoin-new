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
#include "common/buffer.h"
#include "../commands.h"
#include "../constants.h"
#include "../types.h"
#include "client_commands.h"



// TODO: this API is very clumsy, find a better interface.
//       The boilerplate part of ext_get_square could be reduced. The only non-boilerplate code is:
//         - reading the result from the client
//         - serializing the command for SW_INTERRUPTED_EXECUTION

/**
 * If this is a continuation, fetches the response, writes into `result`, then returns 1.
 * If this is an interruption, alerts the dispatcher and prepares the response, then returns 0.
 * If any error occurs, it returs 0.
 **/
int ext_get_square(dispatcher_context_t *dispatcher_context, uint32_t *result, uint8_t n) {
    if (dispatcher_context->is_continuation) {
        dispatcher_context->is_continuation = false;

        // TODO: should only reach here if the interrupted command is GET_SUM_OF_SQUARES
        //       It would make sense to have an integrity check here.

        // read the result from the client
        if (!buffer_read_u32(&dispatcher_context->read_buffer, result, BE)) {
            io_set_response(NULL, 0, SW_WRONG_DATA_LENGTH);
            return 0;
        }

        return 1;
    } else {
        // prepare the EXT_GET_SQUARE response for the user
        uint8_t req[] = { CCMD_GET_SQUARE, n };

        io_set_response(req, 2, SW_INTERRUPTED_EXECUTION);

        dispatcher_context->interrupt = true;
        return 0;
    }
}


int handler_get_sum_of_squares(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dispatcher_context
) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state;
    uint8_t n;

    if (p1 != 0 || p2 != 0) {
        return io_send_sw(SW_WRONG_P1P2);
    }
    if (lc != 1) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }

    if (!buffer_read_u8(&dispatcher_context->read_buffer, &n)){
        return -1;
    }

    state->n = n;
    state->i = 1;
    state->sum = 0;

    return true;
}


int processor_get_sum_of_squares(dispatcher_context_t *dispatcher_context) {
    get_sum_of_squares_state_t *state = (get_sum_of_squares_state_t *)&G_command_state; 
    for ( ; state->i <= state->n; state->i++) {
        uint32_t result;
        if (!ext_get_square(dispatcher_context, &result, state->i)) {
            return io_confirm_response();
        }
        state->sum += result;
    }

    return io_send_response(&state->sum, 4, SW_OK);
}


