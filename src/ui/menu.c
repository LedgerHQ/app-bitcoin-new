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

#include "os.h"
#include "ux.h"

#include "../globals.h"
#include "menu.h"

#ifdef HAVE_BAGL
// We have a screen with the icon and "Bitcoin is ready" for Bitcoin,
// "Bitcoin Testnet is ready" for Bitcoin Testnet.
UX_STEP_NOCB(ux_menu_ready_step_bitcoin, pnn, {&C_bitcoin_logo, "Bitcoin", "is ready"});
UX_STEP_NOCB(ux_menu_ready_step_bitcoin_testnet,
             pnn,
             {&C_bitcoin_logo, "Bitcoin Testnet", "is ready"});

UX_STEP_NOCB(ux_menu_version_step, bn, {"Version", APPVERSION});
UX_STEP_CB(ux_menu_about_step, pb, ui_menu_about(), {&C_icon_certificate, "About"});
UX_STEP_VALID(ux_menu_exit_step, pb, os_sched_exit(-1), {&C_icon_dashboard_x, "Quit"});

// FLOW for the main menu (for bitcoin):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: about submenu
// #4 screen: quit
UX_FLOW(ux_menu_main_flow_bitcoin,
        &ux_menu_ready_step_bitcoin,
        &ux_menu_version_step,
        &ux_menu_about_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

// FLOW for the main menu (for bitcoin testnet):
// #1 screen: ready
// #2 screen: version of the app
// #3 screen: about submenu
// #4 screen: quit
UX_FLOW(ux_menu_main_flow_bitcoin_testnet,
        &ux_menu_ready_step_bitcoin_testnet,
        &ux_menu_version_step,
        &ux_menu_about_step,
        &ux_menu_exit_step,
        FLOW_LOOP);

#endif  // HAVE_BAGL
#define BIP32_PUBKEY_VERSION_MAINNET 0x0488B21E
#define BIP32_PUBKEY_VERSION_TESTNET 0x043587CF

void ui_menu_main() {
#ifdef HAVE_BAGL
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_VERSION_MAINNET) {  // mainnet
        ux_flow_init(0, ux_menu_main_flow_bitcoin, NULL);
    } else if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_VERSION_TESTNET) {  // testnet
        ux_flow_init(0, ux_menu_main_flow_bitcoin_testnet, NULL);
    }
#endif  // HAVE_BAGL
}

#ifdef HAVE_BAGL
UX_STEP_NOCB(ux_menu_info_step, bn, {"Bitcoin App", "(c) 2022 Ledger"});
UX_STEP_CB(ux_menu_back_step, pb, ui_menu_main(), {&C_icon_back, "Back"});

// FLOW for the about submenu:
// #1 screen: app info
// #2 screen: back button to main menu
UX_FLOW(ux_menu_about_flow, &ux_menu_info_step, &ux_menu_back_step, FLOW_LOOP);
#endif  // HAVE_BAGL

void ui_menu_about() {
#ifdef HAVE_BAGL
    ux_flow_init(0, ux_menu_about_flow, NULL);
#endif  // HAVE_BAGL
}
