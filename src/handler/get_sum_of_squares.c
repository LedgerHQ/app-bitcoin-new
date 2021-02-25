/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
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

#include "../constants.h"
#include "../globals.h"
#include "../io.h"
#include "../sw.h"
#include "../types.h"
#include "common/buffer.h"
#include "../apdu/dispatcher.h"
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
            io_set_response(NULL, SW_WRONG_RESPONSE_LENGTH);
            return 0;
        }

        return 1;
    } else {
        // prepare the EXT_GET_SQUARE response for the user
        uint8_t req[] = { CCMD_GET_SQUARE, n };

        int res = io_set_response(&(const buffer_t){.ptr = req, .size = 2, .offset = 0}, SW_INTERRUPTED_EXECUTION);

        dispatcher_context->interrupt = true;
        return 0;
    }
}



bool init_get_sum_of_squares_state(get_sum_of_squares_state_t *state, dispatcher_context_t *dispatcher_context) {
    uint8_t n;

    // TODO: check return value
    if (!buffer_read_u8(&dispatcher_context->read_buffer, &n)){
        return false;
    }

    state->n = n;
    state->i = 1;
    state->sum = 0;
    return true;
}


int handler_get_sum_of_squares(get_sum_of_squares_state_t *state, dispatcher_context_t *dispatcher_context) {
    for ( ; state->i <= state->n; state->i++) {
        uint32_t result;
        if (!ext_get_square(dispatcher_context, &result, state->i)) {
            return io_confirm_response();
        }
        state->sum += result;
    }

    return io_send_response(
        &(const buffer_t){.ptr = (uint8_t *)&state->sum,
                          .size = 4,
                          .offset = 0},
        SW_OK);

}
