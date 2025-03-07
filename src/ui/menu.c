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

#include "os.h"
#include "ux.h"

#include "../globals.h"
#include "menu.h"

#define BIP32_PUBKEY_VERSION_MAINNET 0x0488B21E
#define BIP32_PUBKEY_VERSION_TESTNET 0x043587CF

void ui_menu_main() {
    if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_VERSION_MAINNET) {  // mainnet
        ui_menu_main_flow_bitcoin();
    } else if (BIP32_PUBKEY_VERSION == BIP32_PUBKEY_VERSION_TESTNET) {  // testnet
        ui_menu_main_flow_bitcoin_testnet();
    }
}
