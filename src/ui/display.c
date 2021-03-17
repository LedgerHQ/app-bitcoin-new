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
#include <stdio.h>    // snprintf
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
#include "../constants.h"

#define MAX_BASE58_PUBKEY_LENGTH 112
#define MAX_ADDRESS_LENGTH 35

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.
static action_validate_cb g_validate_callback;
static dispatcher_context_t *g_dispatcher_context;

// TODO: optimize (or avoid?) globals for UX screens.
//       different screens could share the same memory using a union.

static char g_bip32_path[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
static char g_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
static char g_address[MAX_ADDRESS_LENGTH_STR + 1];
static char g_wallet_name[MAX_WALLET_NAME_LENGTH + 1];
static char g_multisig_type[sizeof("15 of 15")];
static char g_multisig_signer_index[sizeof("Signer 15 of 15")];

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
    (*g_validate_callback)(g_dispatcher_context, false),
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
           (*g_validate_callback)(g_dispatcher_context, true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(g_dispatcher_context, false),
           {
               &C_icon_crossmark,
               "Reject",
           });


// Step with icon and text with name of a wallet being registered
UX_STEP_NOCB(
    ux_display_wallet_header_name_step,
    pnn,
    {
      &C_icon_eye,
      "Register wallet",
      g_wallet_name,
    });

// Step with description of a m-of-n multisig wallet
UX_STEP_NOCB(
    ux_display_wallet_multisig_type_step,
    nn,
    {
      "Multisig wallet",
      g_multisig_type,
    });


// Step with index and xpub of a cosigner of a multisig wallet
UX_STEP_NOCB(
    ux_display_wallet_multisig_cosigner_pubkey_step,
    bnnn_paging,
    {
        .title = g_multisig_signer_index,
        .text = g_pubkey,
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


// FLOW to display the header of a multisig wallet:
// #1 screen: eye icon + "Register multisig" and the wallet name
// #2 screen: display multisig threshold and number of keys
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_multisig_header_flow,
        &ux_display_wallet_header_name_step,
        &ux_display_wallet_multisig_type_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display the header of a multisig wallet:
// #1 screen: Cosigner index and pubkey (paginated)
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_multisig_cosigner_pubkey_flow,
        &ux_display_wallet_multisig_cosigner_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);



int ui_display_pubkey(dispatcher_context_t *context, char *bip32_path, char *pubkey, action_validate_cb callback) {
    strncpy(g_bip32_path, bip32_path, sizeof(g_bip32_path));
    strncpy(g_pubkey, pubkey, sizeof(g_pubkey));

    g_dispatcher_context = context;
    g_validate_callback = callback;

    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}


int ui_display_address(dispatcher_context_t *context, char *address, bool is_path_suspicious, action_validate_cb callback) {
    strncpy(g_address, address, sizeof(g_address));

    g_dispatcher_context = context;
    g_validate_callback = callback;

    if (is_path_suspicious) {
        ux_flow_init(0, ux_display_address_flow, NULL);
    } else {
        ux_flow_init(0, ux_display_address_suspicious_flow, NULL);
    }
    return 0;
}


int ui_display_multisig_header(dispatcher_context_t *context, char *name, uint8_t threshold, uint8_t n_keys, action_validate_cb callback) {
    strncpy(g_wallet_name, name, sizeof(g_wallet_name));
    snprintf(g_multisig_type, sizeof(g_multisig_type), "%u of %u", threshold, n_keys);

    g_dispatcher_context = context;
    g_validate_callback = callback;

    ux_flow_init(0, ux_display_multisig_header_flow, NULL);
    return 0;
}


int ui_display_multisig_cosigner_pubkey(dispatcher_context_t *context, char *pubkey, uint8_t cosigner_index, uint8_t n_keys, action_validate_cb callback) {
    strncpy(g_pubkey, pubkey, sizeof(g_pubkey));
    snprintf(g_multisig_signer_index, sizeof(g_multisig_type), "Signer %u of %u", cosigner_index, n_keys);

    g_dispatcher_context = context;
    g_validate_callback = callback;

    ux_flow_init(0, ux_display_multisig_cosigner_pubkey_flow, NULL);
    return 0;
}
