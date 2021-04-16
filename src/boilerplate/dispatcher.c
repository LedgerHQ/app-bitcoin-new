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

extern dispatcher_context_t G_dispatcher_context;

// Private state that is not made accessible from the dispatcher context
struct {
    void (*termination_cb)(void);
    bool paused;
    uint16_t sw;
} G_dispatcher_state;


static void dispatcher_loop();

static void next(command_processor_t next_processor) {
    G_dispatcher_context.machine_context_ptr->next_processor = next_processor;
}


static void send_response(void *rdata, size_t rdata_len, uint16_t sw) {
    G_dispatcher_state.sw = sw;

    io_set_response(rdata, rdata_len, sw);
    io_confirm_response();
}

static void send_sw(uint16_t sw) {
    send_response(NULL, 0, sw);
}

static void pause() {
    G_dispatcher_state.paused = true;
}

static void run() {
    G_dispatcher_state.paused = false;
    dispatcher_loop();
}


int apdu_dispatcher(command_descriptor_t const cmd_descriptors[],
                    int n_descriptors,
                    machine_context_t *top_context,
                    size_t top_context_size,
                    void (*termination_cb)(void),
                    const command_t *cmd) {


    // TODO: decide what to do if a command is sent while something was still running
    // currently: wiping everything

    G_dispatcher_state.termination_cb = termination_cb;
    G_dispatcher_state.paused = false;
    G_dispatcher_state.sw = 0;

    G_dispatcher_context.next = next;
    G_dispatcher_context.send_response = send_response;
    G_dispatcher_context.send_sw = send_sw;
    G_dispatcher_context.pause = pause;
    G_dispatcher_context.run = run;

    G_dispatcher_context.read_buffer.ptr = cmd->data;
    G_dispatcher_context.read_buffer.size = cmd->lc;
    G_dispatcher_context.read_buffer.offset = 0;


    if (cmd->cla == CLA_FRAMEWORK && cmd->ins == INS_CONTINUE) {
        if (cmd->p1 != 0 || cmd->p2 != 0) {
            return io_send_sw(SW_WRONG_P1P2);
        }

        if (G_dispatcher_context.machine_context_ptr == NULL || G_dispatcher_context.machine_context_ptr->next_processor == NULL) {
            PRINTF("Unexpected INS_CONTINUE.\n");
            return io_send_sw(SW_BAD_STATE); // received INS_CONTINUE, but no command was interrupted.
        }


        dispatcher_loop();

    } else {
        // If a previous command was interrupted but any command other than INS_CONTINUE is received,
        // the interrupted command is discarded.

        G_dispatcher_context.machine_context_ptr = top_context;

        // Safety measure: reset to 0 the entire context before starting.
        memset(top_context, 0, top_context_size);

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

        dispatcher_loop();
    }

    return 0;
}

static void dispatcher_loop() {
    if (G_dispatcher_context.machine_context_ptr == NULL) {
        PRINTF("dispatcher_loop called when the machine context is not set.");
        return;
    }

    while (true) {
        PRINTF("DISPATCHER LOOP: %u, %u\n", G_dispatcher_context.machine_context_ptr->next_processor, G_dispatcher_context.machine_context_ptr->parent_context);

        if (G_dispatcher_state.paused) {
            PRINTF("DISPATCHER PAUSED\n");
            return;
        }

        if (G_dispatcher_context.machine_context_ptr->next_processor) {
            // the current submachine ended, continue to parent's context
            command_processor_t proc = G_dispatcher_context.machine_context_ptr->next_processor;
            G_dispatcher_context.machine_context_ptr->next_processor = NULL;
            proc(&G_dispatcher_context);

            // if an interruption is sent, should exit the loop and persist the context for the next call
            // in that case, there MUST be a next_processor
            if (G_dispatcher_state.sw == SW_INTERRUPTED_EXECUTION) {
                if (G_dispatcher_context.machine_context_ptr->next_processor == NULL) {
                    PRINTF("Interruption requested, but the next processor was not set.");
                }
                return;
            }

        } else if (G_dispatcher_context.machine_context_ptr->parent_context != NULL) {
            // the current submachine ended, continue from parent's context
            G_dispatcher_context.machine_context_ptr = G_dispatcher_context.machine_context_ptr->parent_context;
            continue;
        } else {
            break; // all done
        }
    }

    // call the termination callback (e.g. to return to main menu), if given
    if (G_dispatcher_state.termination_cb != NULL) {
        G_dispatcher_state.termination_cb();
    }
}
