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
#include <string.h>  // memset, explicit_bzero

#include <assert.h>

#include "os.h"
#include "ux.h"

#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

#include "debug-helpers/debug.h"

#include "handler/handlers.h"
#include "commands.h"

#include "common/wallet.h"

// common declarations between legacy and new code; will refactor it out later
#include "swap/swap_lib_calls.h"
#include "swap/swap_globals.h"
#include "swap/handle_swap_sign_transaction.h"
#include "swap/handle_get_printable_amount.h"
#include "swap/handle_check_address.h"

#ifdef HAVE_NBGL
#include "nbgl_use_case.h"
#endif

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

dispatcher_context_t G_dispatcher_context;

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

void app_main() {
    for (;;) {
        // Length of APDU command received in G_io_apdu_buffer
        int input_len = 0;
        // Structured APDU command
        command_t cmd;

        // Reset length of APDU response
        G_output_len = 0;

        // Receive command bytes in G_io_apdu_buffer

        input_len = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);

        if (input_len < 0) {
            PRINTF("=> io_exchange error\n");
            return;
        }

        // Reset structured APDU command
        memset(&cmd, 0, sizeof(cmd));
        // Parse APDU command from G_io_apdu_buffer
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
            io_send_sw(SW_WRONG_DATA_LENGTH);
            return;
        }

        PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=",
               cmd.cla,
               cmd.ins,
               cmd.p1,
               cmd.p2,
               cmd.lc);
        for (int i = 0; i < cmd.lc; i++) {
            PRINTF("%02X", cmd.data[i]);
        }
        PRINTF("\n");

        if (G_swap_state.called_from_swap) {
            if (cmd.cla != CLA_APP) {
                io_send_sw(SW_CLA_NOT_SUPPORTED);
                continue;
            }
            if (cmd.ins != GET_EXTENDED_PUBKEY && cmd.ins != GET_WALLET_ADDRESS &&
                cmd.ins != SIGN_PSBT && cmd.ins != GET_MASTER_FINGERPRINT) {
                PRINTF(
                    "Only GET_EXTENDED_PUBKEY, GET_WALLET_ADDRESS, SIGN_PSBT and "
                    "GET_MASTER_FINGERPRINT can be called during swap\n");
                io_send_sw(SW_INS_NOT_SUPPORTED);
                continue;
            }
        }

        // Dispatch structured APDU command to handler
        apdu_dispatcher(COMMAND_DESCRIPTORS,
                        sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                        ui_menu_main,
                        &cmd);

        if (G_swap_state.called_from_swap && G_swap_state.should_exit) {
            // Bitcoin app will keep listening as long as it does not receive a valid TX
            finalize_exchange_sign_transaction(true);
        }
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

static void initialize_app_globals() {
    io_reset_timeouts();

    // We only zero the called_from_swap and should_exit fields and not the entire G_swap_state, as
    // we need the globals initialization to happen _after_ calling copy_transaction_parameters when
    // processing a SIGN_TRANSACTION request from the swap app (which initializes the other fields
    // of G_swap_state).
    G_swap_state.called_from_swap = false;
    G_swap_state.should_exit = false;
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void coin_main() {
    PRINT_STACK_POINTER();

    initialize_app_globals();

    // assumptions on the length of data structures

    _Static_assert(sizeof(cx_sha256_t) <= 108, "cx_sha256_t too large");
    _Static_assert(sizeof(policy_map_key_info_t) <= 156, "policy_map_key_info_t too large");

#if defined(HAVE_PRINT_STACK_POINTER) && defined(HAVE_BOLOS_APP_STACK_CANARY)
    PRINTF("STACK CANARY ADDRESS: %08x\n", &app_stack_canary);
#endif

    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));

    memset(G_io_apdu_buffer, 0, 255);  // paranoia

    // Process the incoming APDUs

    for (;;) {
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef HAVE_BLE
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // HAVE_BLE

                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
}

static void swap_library_main_helper(libargs_t *args) {
    check_api_level(CX_COMPAT_APILEVEL);
    PRINTF("Inside a library \n");
    switch (args->command) {
        case CHECK_ADDRESS:
            // ensure result is zero if an exception is thrown
            args->check_address->result = 0;
            args->check_address->result = handle_check_address(args->check_address);
            break;
        case SIGN_TRANSACTION: {
            // copying arguments (pointing to globals) to context *before*
            // calling `initialize_app_globals` as it could override them
            const bool args_are_copied = copy_transaction_parameters(args->create_transaction);
            initialize_app_globals();
            if (args_are_copied) {
                // never returns

                G_swap_state.called_from_swap = 1;

                io_seproxyhal_init();
                UX_INIT();
#ifdef HAVE_BAGL
                ux_stack_push();
#elif defined(HAVE_NBGL)
                nbgl_useCaseSpinner("Signing");
#endif  // HAVE_BAGL

                USB_power(0);
                USB_power(1);
                // ui_idle();
                PRINTF("USB power ON/OFF\n");
#ifdef HAVE_BLE
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
                BLE_power(0, NULL);
                BLE_power(1, NULL);
#endif  // HAVE_BLE
                app_main();
            }
            break;
        }
        case GET_PRINTABLE_AMOUNT:
            // ensure result is zero if an exception is thrown (compatibility breaking, disabled
            // until LL is ready)
            // args->get_printable_amount->result = 0;
            // args->get_printable_amount->result =
            handle_get_printable_amount(args->get_printable_amount);
            break;
        default:
            break;
    }
}

void swap_library_main(libargs_t *args) {
    bool end = false;
    /* This loop ensures that swap_library_main_helper and os_lib_end are called
     * within a try context, even if an exception is thrown */
    while (1) {
        BEGIN_TRY {
            TRY {
                if (!end) {
                    swap_library_main_helper(args);
                }
                os_lib_end();
            }
            FINALLY {
                end = true;
            }
        }
        END_TRY;
    }
}

__attribute__((section(".boot"))) int main(int arg0) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    if (!arg0) {
        // Application launched from dashboard
        coin_main();
        return 0;
    }

    // Application launched as library (for swap support)
    libargs_t *args = (libargs_t *) arg0;
    if (args->id != 0x100) {
        app_exit();
        return 0;
    }

    swap_library_main(args);

    return 0;
}
