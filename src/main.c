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

#include "commands.h"

#include "legacy/main_old.h"
#include "legacy/btchip_display_variables.h"
#include "legacy/include/swap_lib_calls.h"
#include "legacy/include/btchip_context.h"

#include "main.h"

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

#ifdef TARGET_NANOS
// on NanoS only, we optimize the usage of the globals with a custom linker script
command_state_t __attribute__((section(".new_globals"))) G_command_state;
dispatcher_context_t __attribute__((section(".new_globals"))) G_dispatcher_context;

// legacy variables
btchip_context_t __attribute__((section(".legacy_globals"))) btchip_context_D;
#else
command_state_t G_command_state;
dispatcher_context_t G_dispatcher_context;

// legacy variables
btchip_context_t btchip_context_D;
#endif

// shared between legacy and new
global_context_t *G_coin_config;  // same type as btchip_altcoin_config_t

uint8_t G_app_mode;

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_PUBKEY,
        .handler = (command_handler_t)handler_get_pubkey
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
};
// clang-format on

void init_coin_config(btchip_altcoin_config_t *coin_config) {
    memset(coin_config, 0, sizeof(btchip_altcoin_config_t));

    // new app
    coin_config->bip32_pubkey_version = BIP32_PUBKEY_VERSION;

    // legacy
    coin_config->bip44_coin_type = BIP44_COIN_TYPE;
    coin_config->bip44_coin_type2 = BIP44_COIN_TYPE_2;
    coin_config->p2pkh_version = COIN_P2PKH_VERSION;
    coin_config->p2sh_version = COIN_P2SH_VERSION;
    coin_config->family = COIN_FAMILY;
    strcpy(coin_config->coinid, COIN_COINID);
    strcpy(coin_config->name, COIN_COINID_NAME);
    strcpy(coin_config->name_short, COIN_COINID_SHORT);
#ifdef COIN_NATIVE_SEGWIT_PREFIX
    strcpy(coin_config->native_segwit_prefix_val, COIN_NATIVE_SEGWIT_PREFIX);
    coin_config->native_segwit_prefix = coin_config->native_segwit_prefix_val;
#else
    coin_config->native_segwit_prefix = 0;
#endif  // #ifdef COIN_NATIVE_SEGWIT_PREFIX
#ifdef COIN_FORKID
    coin_config->forkid = COIN_FORKID;
#endif  // COIN_FORKID
#ifdef COIN_CONSENSUS_BRANCH_ID
    coin_config->zcash_consensus_branch_id = COIN_CONSENSUS_BRANCH_ID;
#endif  // COIN_CONSENSUS_BRANCH_ID
#ifdef COIN_FLAGS
    coin_config->flags = COIN_FLAGS;
#endif  // COIN_FLAGS
    coin_config->kind = COIN_KIND;
}

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

        if (G_io_apdu_buffer[0] == CLA_APP_LEGACY) {
            if (G_app_mode != APP_MODE_LEGACY) {
                explicit_bzero(&btchip_context_D, sizeof(btchip_context_D));

                btchip_context_init();

                G_app_mode = APP_MODE_LEGACY;
            }

            if (btchip_context_D.called_from_swap && vars.swap_data.should_exit) {
                btchip_context_D.io_flags |= IO_RETURN_AFTER_TX;
            }

            // legacy codes, use old dispatcher
            btchip_context_D.inLength = input_len;

            app_dispatch();

            if (btchip_context_D.called_from_swap && vars.swap_data.should_exit) {
                os_sched_exit(0);
            }
        } else {
            if (G_app_mode != APP_MODE_NEW) {
                explicit_bzero(&G_command_state, sizeof(G_command_state));

                G_app_mode = APP_MODE_NEW;
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

            // Dispatch structured APDU command to handler
            apdu_dispatcher(COMMAND_DESCRIPTORS,
                            sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                            (machine_context_t *) &G_command_state,
                            sizeof(G_command_state),
                            ui_menu_main,
                            &cmd);
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
 * Handle APDU command received and send back APDU response using handlers.
 */
void coin_main(btchip_altcoin_config_t *coin_config) {
    PRINT_STACK_POINTER();

    // assumptions on the length of data structures

    _Static_assert(sizeof(cx_sha256_t) <= 108, "cx_sha256_t too large");
    _Static_assert(sizeof(policy_map_key_info_t) <= 148, "policy_map_key_info_t too large");

    btchip_altcoin_config_t config;
    if (coin_config == NULL) {
        init_coin_config(&config);
        G_coin_config = &config;
    } else {
        G_coin_config = coin_config;
    }

#if defined(HAVE_PRINT_STACK_POINTER) && defined(HAVE_BOLOS_APP_STACK_CANARY)
    PRINTF("STACK CANARY ADDRESS: %08x\n", &app_stack_canary);
#endif

#ifdef HAVE_SEMIHOSTED_PRINTF
    PRINTF("APDU State size: %d\n", sizeof(command_state_t));
    PRINTF("Legacy State size: %d\n", sizeof(btchip_context_D));
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

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                ui_idle();

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

__attribute__((section(".boot"))) int main(int arg0) {
    G_app_mode = APP_MODE_UNINITIALIZED;

#ifdef USE_LIB_BITCOIN
    BEGIN_TRY {
        TRY {
            unsigned int libcall_params[5];
            btchip_altcoin_config_t coin_config;
            init_coin_config(&coin_config);

            G_app_mode =
                APP_MODE_LEGACY;  // in library mode, we currently only run with legacy APDUs

            PRINTF("Hello from litecoin\n");
            check_api_level(CX_COMPAT_APILEVEL);
            // delegate to bitcoin app/lib
            libcall_params[0] = "Bitcoin";
            libcall_params[1] = 0x100;
            libcall_params[2] = RUN_APPLICATION;
            libcall_params[3] = &coin_config;
            libcall_params[4] = 0;
            if (arg0) {
                // call as a library
                libcall_params[2] = ((unsigned int *) arg0)[1];
                libcall_params[4] = ((unsigned int *) arg0)[3];  // library arguments
                os_lib_call(&libcall_params);
                ((unsigned int *) arg0)[0] = libcall_params[1];
                os_lib_end();
            } else {
                // launch coin application
                os_lib_call(&libcall_params);
            }
        }
        FINALLY {
        }
    }
    END_TRY;
    // no return
#else
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    if (!arg0) {
        // Bitcoin application launched from dashboard
        coin_main(NULL);
        return 0;
    }

    struct libargs_s *args = (struct libargs_s *) arg0;
    if (args->id != 0x100) {
        app_exit();
        return 0;
    }
    switch (args->command) {
        case RUN_APPLICATION:
            // coin application launched from dashboard
            if (args->coin_config == NULL)
                app_exit();
            else
                coin_main(args->coin_config);
            break;
        default:
            // called as bitcoin or altcoin library
            library_main(args);
    }
#endif  // USE_LIB_BITCOIN
    return 0;
}
