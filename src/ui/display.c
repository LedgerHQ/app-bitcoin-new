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

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../boilerplate/io.h"
#include "../boilerplate/sw.h"
#include "../common/bip32.h"
#include "../common/format.h"


#define MAX_BIP32_PATH_LENGTH 60 // TODO: could likely be longer; check
#define MAX_BASE58_PUBKEY_LENGTH 112
#define MAX_ADDRESS_LENGTH 35

static action_validate_cb g_validate_callback;
static char g_bip32_path[MAX_BIP32_PATH_LENGTH + 1];
static char g_pubkey[MAX_BASE58_PUBKEY_LENGTH + 1];
static char g_address[MAX_ADDRESS_LENGTH + 1];

// Step with icon and text for pubkey
UX_STEP_NOCB(ux_display_confirm_pubkey_step, pn, {&C_icon_eye, "Confirm public key"});

// Step with icon and text for address
UX_STEP_NOCB(ux_display_confirm_address_step, pn, {&C_icon_eye, "Confirm receive address"});

// Step with icon and text for a suspicious address
UX_STEP_NOCB(
    ux_display_unusual_derivation_path_step,
    pnn,
    {
      &C_icon_warning,
      "The derivation",
      "path is unusual!",
    });

// Step with icon and text to caution the user to reject if unsure
UX_STEP_CB(
    ux_display_reject_if_not_sure_step,
    pnn,
    (*g_validate_callback)(false),
    {
      &C_icon_crossmark,
      "Reject if you're",
      "not sure",
    });

// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_bip32_path,
             });

// Step with title/text for pubkey
UX_STEP_NOCB(ux_display_pubkey_step,
             bnnn_paging,
             {
                 .title = "Public key",
                 .text = g_pubkey,
             });

// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_address,
             });

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {
               &C_icon_crossmark,
               "Reject",
           });

// FLOW to display BIP32 path and pubkey:
// #1 screen: eye icon + "Confirm Pubkey"
// #2 screen: display BIP32 Path
// #3 screen: display pubkey
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_pubkey_step,
        &ux_display_path_step,
        &ux_display_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display a receive address, for a standard path:
// #1 screen: eye icon + "Confirm Address"
// #3 screen: display address
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_address_flow,
        &ux_display_confirm_address_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display a receive address, for a non-standard path:
// #1 screen: warning icon + "The derivation path is unusual!"
// #2 screen: display BIP32 Path
// #3 screen: crossmark icon + "Reject if not sure" (user can reject here)
// #4 screen: eye icon + "Confirm Address"
// #5 screen: display address
// #6 screen: approve button
// #7 screen: reject button
UX_FLOW(ux_display_address_suspicious_flow,
        &ux_display_unusual_derivation_path_step,
        &ux_display_path_step,
        &ux_display_reject_if_not_sure_step,
        &ux_display_confirm_address_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


int ui_display_pubkey(char *bip32_path, char *pubkey, action_validate_cb callback) {
    strncpy(g_bip32_path, bip32_path, sizeof(g_bip32_path));
    strncpy(g_pubkey, pubkey, sizeof(g_pubkey));

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}


int ui_display_address(char *address, bool is_path_suspicious, action_validate_cb callback) {
    strncpy(g_address, address, sizeof(g_address));
    g_validate_callback = callback;

    if (is_path_suspicious) {
        ux_flow_init(0, ux_display_address_flow, NULL);
    } else {
        ux_flow_init(0, ux_display_address_suspicious_flow, NULL);
    }
    return 0;
}
