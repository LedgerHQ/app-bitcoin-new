/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2025 Ledger SAS.
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

#include <assert.h>
#include <stdint.h>
#include <string.h>

/* SDK headers */
#include "nbgl_use_case.h"
#include "io.h"
#include "os.h"
#ifdef HAVE_SWAP
#include "swap.h"
#endif /* HAVE_SWAP */
#include "ux.h"

/* Local headers */
#include "commands.h"
#include "constants.h"
#include "debug.h"
#include "dispatcher.h"
#ifdef HAVE_SWAP
#include "handle_swap_sign_transaction.h"
#endif /* HAVE_SWAP */
#include "handlers.h"
#include "io_ext.h"
#include "menu.h"
#include "parser.h"
#include "sw.h"
#ifdef HAVE_SWAP
#include "swap_globals.h"
#endif /* HAVE_SWAP */
#include "wallet.h"

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

dispatcher_context_t G_dispatcher_context;

extern const char GA_SIGNING_TRANSACTION[];

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_EXTENDED_PUBKEY,
        .handler = (command_handler_t)handler_get_extended_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = REGISTER_WALLET,
        .handler = (command_handler_t)handler_register_wallet
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_PSBT,
        .handler = (command_handler_t)handler_sign_psbt
    },
    {
        .cla = CLA_APP,
        .ins = GET_MASTER_FINGERPRINT,
        .handler = (command_handler_t)handler_get_master_fingerprint
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_MESSAGE,
        .handler = (command_handler_t)handler_sign_message
    },
};
// clang-format on

static void initialize_app_globals() {
    ioe_reset_timeouts();

    // We only zero out should_exit field and not the entire G_swap_state, as
    // we need the globals initialization to happen _after_ calling copy_transaction_parameters when
    // processing a SIGN_TRANSACTION request from the swap app (which initializes the other fields
    // of G_swap_state).
#ifdef HAVE_SWAP
    G_swap_state.should_exit = false;
#endif /* HAVE_SWAP */
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void app_main() {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    // Structured APDU command
    command_t cmd;

    io_init();

#ifdef HAVE_SWAP
    // When called in swap context as a library, we don't want to show the menu
    if (!G_called_from_swap) {
#endif
        ui_menu_main();
#ifdef HAVE_SWAP
    }
#endif

    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));
    memset(G_io_apdu_buffer, 0, sizeof(G_io_apdu_buffer));  // paranoia

    for (;;) {
        // Reset length of APDU response
        G_output_len = 0;

        initialize_app_globals();

        // Receive command bytes in G_io_apdu_buffer
        if ((input_len = io_recv_command()) < 0) {
            PRINTF("=> io_recv_command failure\n");
            return;
        }

        // Reset structured APDU command
        memset(&cmd, 0, sizeof(cmd));
        // Parse APDU command from G_io_apdu_buffer
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
            ioe_send_sw(SW_WRONG_DATA_LENGTH);
            continue;
        }

        PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=%.*H\n",
               cmd.cla,
               cmd.ins,
               cmd.p1,
               cmd.p2,
               cmd.lc,
               cmd.lc,
               cmd.data);
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            if (cmd.cla != CLA_APP) {
                ioe_send_sw(SW_CLA_NOT_SUPPORTED);
                continue;
            }
            if (cmd.ins != GET_EXTENDED_PUBKEY && cmd.ins != GET_WALLET_ADDRESS &&
                cmd.ins != SIGN_PSBT && cmd.ins != GET_MASTER_FINGERPRINT) {
                PRINTF(
                    "Only GET_EXTENDED_PUBKEY, GET_WALLET_ADDRESS, SIGN_PSBT and "
                    "GET_MASTER_FINGERPRINT can be called during swap\n");
                ioe_send_sw(SW_INS_NOT_SUPPORTED);
                continue;
            }
        }

#endif /* HAVE_SWAP */
        // Dispatch structured APDU command to handler
        apdu_dispatcher(COMMAND_DESCRIPTORS,
                        sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                        ui_menu_main,
                        &cmd);
#ifdef HAVE_SWAP
        if (G_called_from_swap && G_swap_state.should_exit) {
            // Bitcoin app will keep listening as long as it does not receive a valid TX
            finalize_exchange_sign_transaction(true);
        }
#endif /* HAVE_SWAP */
    }
}
