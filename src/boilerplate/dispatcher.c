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
#include <stdbool.h>

#include "dispatcher.h"
#include "constants.h"
#include "../constants.h"
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "types.h"
#include "../types.h"
#include "../common/buffer.h"
#include "../handler/get_sum_of_squares.h"

/**
 * Information about an interrupted command (if any).
 */
struct {
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
} G_interrupted_command;

int apdu_dispatcher(const command_t *cmd) {
    int ins = cmd->ins, p1 = cmd->p1, p2 = cmd->p2;
    dispatcher_context_t dispatcher_context = {
        .interrupt = false, // set to true if the execution is interrupted for a client command
        .is_continuation = false,
        .read_buffer = {
            .ptr = cmd->data,
            .size = cmd->lc,
            .offset = 0
        }
    };

    if (cmd->cla == CLA_FRAMEWORK && ins == INS_CONTINUE) {
        dispatcher_context.is_continuation = true;
        if (cmd->p1 != 0 || cmd->p2 != 0) {
            return io_send_sw(SW_WRONG_P1P2);
        }

        // Set ins, p1 and p2 as previously set for the interrupted command.
        // Note that lc and data still refer to the continuation command instead.
        ins = G_interrupted_command.ins;
        p1 = G_interrupted_command.p1;
        p2 = G_interrupted_command.p2;
    } else if (cmd->cla != CLA_APP) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }


    // Reset info about the interrupted command (if any)
    G_interrupted_command.ins = 0;
    G_interrupted_command.p1 = 0;
    G_interrupted_command.p2 = 0;

    int ret;
    switch (ins) {
        case GET_SUM_OF_SQUARES:
            if (p1 != 0 || p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }
            if (cmd->lc != 1 && !dispatcher_context.is_continuation) { // ugly, find a better way to avoid these checks on CONTINUE
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }
            if (!dispatcher_context.is_continuation) {
                init_get_sum_of_squares_state(&G_command_state.get_sum_of_squares_state, &dispatcher_context);
            }
            ret = handler_get_sum_of_squares(&G_command_state.get_sum_of_squares_state, &dispatcher_context);
            break;
        default:
            ret = io_send_sw(SW_INS_NOT_SUPPORTED);
    }

    if (dispatcher_context.interrupt == true) {
        // store which command was interrupted
        G_interrupted_command.ins = ins;
        G_interrupted_command.p1 = p1;
        G_interrupted_command.p2 = p2;
    }

    return ret;
}
