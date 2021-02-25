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

#include <stdint.h>
#include <stdbool.h>

#include "dispatcher.h"
#include "../constants.h"
#include "../globals.h"
#include "../types.h"
#include "../io.h"
#include "../sw.h"
#include "../common/buffer.h"
#include "../handler/get_version.h"
#include "../handler/get_app_name.h"
#include "../handler/get_public_key.h"
#include "../handler/sign_tx.h"
#include "../handler/get_sum_of_squares.h"


int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    }

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

    if (ins == CONTINUE) {
        dispatcher_context.is_continuation = true;
        if (cmd->p1 != 0 || cmd->p2 != 0) {
            return io_send_sw(SW_WRONG_P1P2);
        }

        // Set ins, p1 and p2 as previously set for the interrupted command.
        // Note that lc and data still refer to the continuation command instead.
        ins = G_interrupted_command.ins;
        p1 = G_interrupted_command.p1;
        p2 = G_interrupted_command.p2;
    }

    // Reset info about the interrupted command (if any)
    G_interrupted_command.ins = 0;
    G_interrupted_command.p1 = 0;
    G_interrupted_command.p2 = 0;

    int ret;
    switch (ins) {
        case GET_VERSION:
            if (p1 != 0 || p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            ret = handler_get_version();
            break;
        case GET_APP_NAME:
            if (p1 != 0 || p2 != 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            ret = handler_get_app_name();
            break;
        case GET_PUBLIC_KEY:
            if (p1 > 1 || p2 > 0) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            ret = handler_get_public_key(&dispatcher_context.read_buffer, (bool) p1);
            break;
        case SIGN_TX:
            if ((p1 == P1_START && p2 != P2_MORE) ||  //
                p1 > P1_MAX ||                             //
                (p2 != P2_LAST && p2 != P2_MORE)) {
                return io_send_sw(SW_WRONG_P1P2);
            }

            if (!cmd->data) {
                return io_send_sw(SW_WRONG_DATA_LENGTH);
            }

            ret = handler_sign_tx(&dispatcher_context.read_buffer, p1, (bool) (p2 & P2_MORE));
            break;
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
