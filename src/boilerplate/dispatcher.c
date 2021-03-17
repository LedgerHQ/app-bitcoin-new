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
 * If there was an interrupted command, a CONTINUE will restart from the command processor stored here.
 * Otherwise, this must be set to NULL.
 */
extern command_processor_t G_command_continuation;
extern dispatcher_context_t G_dispatcher_context;

int apdu_dispatcher(command_descriptor_t const cmd_descriptors[], int n_descriptors, const command_t *cmd) {
    // TODO: decide what to do if a command is sent while something was still running

    G_dispatcher_context.is_continuation = false;
    G_dispatcher_context.continuation = NULL;
    G_dispatcher_context.read_buffer.ptr = cmd->data;
    G_dispatcher_context.read_buffer.size = cmd->lc;
    G_dispatcher_context.read_buffer.offset = 0;

    if (cmd->cla == CLA_FRAMEWORK && cmd->ins == INS_CONTINUE) {
        if (cmd->p1 != 0 || cmd->p2 != 0) {
            return io_send_sw(SW_WRONG_P1P2);
        }

        if (G_command_continuation == NULL) {
            return io_send_sw(SW_BAD_STATE); // received INS_CONTINUE, but no command was interrupted.
        }

        G_dispatcher_context.is_continuation = true;
        command_processor_t continuation = (command_processor_t)PIC(G_command_continuation);

        // Reset interrupted command
        G_command_continuation = NULL;

        continuation(&G_dispatcher_context);
    } else {
        // Reset interrupted command. If a previous command was interrupted but any command other than
        // INS_CONTINUE is received, the interrupted command is therefore discarded.
        G_command_continuation = NULL;

        bool cla_found = false, ins_found = false;
        command_handler_t handler;
        for (int i = 0; i < n_descriptors; i++) {
            if (cmd_descriptors[i].cla != cmd->cla)
                continue;
            cla_found = true;
            if (cmd_descriptors[i].ins != cmd->ins)
                continue;
            ins_found = true;

            handler = (command_handler_t)PIC(cmd_descriptors[i].handler);
            break;
        }

        if (!cla_found) {
            return io_send_sw(SW_CLA_NOT_SUPPORTED);
        } else if (!ins_found) {
            return io_send_sw(SW_INS_NOT_SUPPORTED);
        }

        handler(cmd->p1, cmd->p2, cmd->lc, &G_dispatcher_context);
    }

    return 0;
}
