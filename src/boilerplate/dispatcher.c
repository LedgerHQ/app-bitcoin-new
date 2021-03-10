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
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "types.h"

#include "common/buffer.h"

/**
 * Information about an interrupted command (if any).
 */
struct {
    bool has_interrupted_command;
    uint8_t cla;                   // Instruction class
    uint8_t ins;                   // Instruction code
    uint8_t p1;                    // Instruction parameter 1
    uint8_t p2;                    // Instruction parameter 2
} G_interrupted_command;

int apdu_dispatcher(command_descriptor_t const cmd_descriptors[], int n_descriptors, const command_t *cmd) {
    uint8_t cla = cmd->cla, ins = cmd->ins, p1 = cmd->p1, p2 = cmd->p2;
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

        if (!G_interrupted_command.has_interrupted_command) {
            return io_send_sw(SW_BAD_STATE);
        }

        // Set cla, ins, p1 and p2 as previously set for the interrupted command.
        // Note that lc and data still refer to the continuation command instead.
        cla = G_interrupted_command.cla;
        ins = G_interrupted_command.ins;
        p1 = G_interrupted_command.p1;
        p2 = G_interrupted_command.p2;
    }

    // Reset interrupted command (if any)
    G_interrupted_command.has_interrupted_command = false;

    int ret = 0;
    bool cla_found = false, ins_found = false;
    for (int i = 0; i < n_descriptors; i++) {
        if (cmd_descriptors[i].cla != cla)
            continue;
        cla_found = true;
        if (cmd_descriptors[i].ins != ins)
            continue;
        ins_found = true;

        if (!dispatcher_context.is_continuation) {
            command_handler_t handler = (command_handler_t)PIC(cmd_descriptors[i].handler);
            ret = handler(p1, p2, cmd->lc, &dispatcher_context);
            if (ret < 0) {
                break;
            }
        }
        if (cmd_descriptors[i].processor != NULL) {
            command_processor_t processor = (command_processor_t)PIC(cmd_descriptors[i].processor);
            ret = processor(&dispatcher_context);
        }
        break;
    }

    if (!cla_found) {
        return io_send_sw(SW_CLA_NOT_SUPPORTED);
    } else if (!ins_found) {
        return io_send_sw(SW_INS_NOT_SUPPORTED);
    }

    if (dispatcher_context.interrupt == true) {
        // store which command was interrupted
        G_interrupted_command.has_interrupted_command = true;
        G_interrupted_command.cla = cla;
        G_interrupted_command.ins = ins;
        G_interrupted_command.p1 = p1;
        G_interrupted_command.p2 = p2;
    }

    return ret;
}
