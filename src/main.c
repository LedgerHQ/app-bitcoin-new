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

#include "os.h"
#include "ux.h"

#include "types.h"
#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "boilerplate/parser.h"
#include "boilerplate/dispatcher.h"

#include "handler/get_pubkey.h"
#include "handler/get_address.h"
#include "handler/get_sum_of_squares.h"
#include "handler/register_wallet.h"
#include "handler/get_wallet_address.h"

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
io_state_e G_io_state;
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;
global_context_t G_context;
command_state_t G_command_state;

command_processor_t G_command_continuation;
dispatcher_context_t G_dispatcher_context;

const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_PUBKEY,
        .handler = (command_handler_t)handler_get_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_ADDRESS,
        .handler = (command_handler_t)handler_get_address
    },
    {
        .cla = CLA_APP,
        .ins = REGISTER_WALLET,
        .handler = (command_handler_t)handler_register_wallet
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = GET_SUM_OF_SQUARES,
        .handler = (command_handler_t)handler_get_sum_of_squares
    }
};


/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void app_main() {
    // Length of APDU command received in G_io_apdu_buffer
    int input_len = 0;
    // Structured APDU command
    command_t cmd;

    // Reset length of APDU response
    G_output_len = 0;
    G_io_state = READY;

    // Reset context
    explicit_bzero(&G_context, sizeof(G_context));
    G_context.bip32_pubkey_version = BIP32_PUBKEY_VERSION;
    static uint32_t const coin_types[] = BIP44_COIN_TYPES;
    G_context.bip44_coin_types_len = sizeof(coin_types)/sizeof(coin_types[0]); 
    G_context.bip44_coin_types = coin_types;

    G_context.p2pkh_version = COIN_P2PKH_VERSION;
    G_context.p2sh_version = COIN_P2SH_VERSION;

#ifdef COIN_NATIVE_SEGWIT_PREFIX
    static char *native_segwit_prefix = COIN_NATIVE_SEGWIT_PREFIX;
    G_context.native_segwit_prefix = (char const *)PIC(native_segwit_prefix);
#else
    coin_config->native_segwit_prefix = 0;
#endif // #ifdef COIN_NATIVE_SEGWIT_PREFIX


    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));
    G_command_continuation = NULL;

    for (;;) {
        BEGIN_TRY {
            TRY {
                // Reset structured APDU command
                memset(&cmd, 0, sizeof(cmd));

                // Receive command bytes in G_io_apdu_buffer
                if ((input_len = io_recv_command()) < 0) {
                    return;
                }

                // Parse APDU command from G_io_apdu_buffer
                if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
                    PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
                    io_send_sw(SW_WRONG_DATA_LENGTH);
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

                // Dispatch structured APDU command to handler
                int n_command_descriptors = sizeof(COMMAND_DESCRIPTORS)/sizeof(COMMAND_DESCRIPTORS[0]);
                if (apdu_dispatcher(COMMAND_DESCRIPTORS, n_command_descriptors, &cmd) < 0) {
                    return;
                }
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                io_send_sw(e);
            }
            FINALLY {
            }
            END_TRY;
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

/**
 * Main loop to setup USB, Bluetooth, UI and launch app_main().
 */
__attribute__((section(".boot"))) int main() {
    __asm volatile("cpsie i");

    os_boot();

    for (;;) {
        // Reset UI
        memset(&G_ux, 0, sizeof(G_ux));

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef TARGET_NANOX
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

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

    return 0;
}
