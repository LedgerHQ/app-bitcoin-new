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
#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../boilerplate/io.h"
#include "../boilerplate/sw.h"
#include "../common/bip32.h"
#include "../common/format.h"
#include "../constants.h"

#define MAX_BASE58_PUBKEY_LENGTH 112
#define MAX_ADDRESS_LENGTH       35

// up to 5 chars for ticker, 1 space, up to 20 digits (20 = digits of 2^64), + 1 decimal separator
#define MAX_AMOUNT_LENGTH (5 + 1 + 20 + 1)

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.
static action_validate_cb g_validate_callback;

extern dispatcher_context_t G_dispatcher_context;

// TODO: hard to keep track of what globals are used in the same flows
//       (especially since the same flow step can be shared in different flows)

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
} ui_path_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} ui_path_and_pubkey_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_path_and_address_state_t;

typedef struct {
    char bip32_path_str[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char hash_hex[64 + 1];
} ui_path_and_hash_state_t;

typedef struct {
    char wallet_name[MAX_WALLET_NAME_LENGTH + 1];
    char policy_map[MAX_POLICY_MAP_STR_LENGTH];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_wallet_state_t;

typedef struct {
    char pubkey[MAX_POLICY_KEY_INFO_LEN + 1];
    char signer_index[sizeof("Key @999 <theirs>")];
} ui_cosigner_pubkey_and_index_state_t;

typedef struct {
    char index[sizeof("output #999")];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
    char amount[MAX_AMOUNT_LENGTH + 1];
} ui_validate_output_state_t;

typedef struct {
    char fee[MAX_AMOUNT_LENGTH + 1];
} ui_validate_transaction_state_t;

/**
 * Union of all the states for each of the UI screens, in order to save memory.
 */
typedef union {
    ui_path_and_pubkey_state_t path_and_pubkey;
    ui_path_and_address_state_t path_and_address;
    ui_path_and_hash_state_t path_and_hash;
    ui_wallet_state_t wallet;
    ui_cosigner_pubkey_and_index_state_t cosigner_pubkey_and_index;
    ui_validate_output_state_t validate_output;
    ui_validate_transaction_state_t validate_transaction;
} ui_state_t;

#ifdef TARGET_NANOS
ui_state_t __attribute__((section(".new_globals"))) g_ui_state;
#else
ui_state_t g_ui_state;
#endif

/*
    STATELESS STEPS
    As these steps do not access per-step globals (except possibly a callback), they can be used in
   any flow.
*/

// Step with icon and text for pubkey
UX_STEP_NOCB(ux_display_confirm_pubkey_step, pn, {&C_icon_eye, "Confirm public key"});

// Step with icon and text for address
UX_STEP_NOCB(ux_display_confirm_address_step, pn, {&C_icon_eye, "Confirm receive address"});

// Step with icon and text for a suspicious address
UX_STEP_NOCB(ux_display_unusual_derivation_path_step,
             pnn,
             {
                 &C_icon_warning,
                 "The derivation",
                 "path is unusual",
             });

// Step with icon and text to caution the user to reject if unsure
UX_STEP_CB(ux_display_reject_if_not_sure_step,
           pnn,
           (*g_validate_callback)(&G_dispatcher_context, false),
           {
               &C_icon_crossmark,
               "Reject if you're",
               "not sure",
           });

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(&G_dispatcher_context, true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Step with approve button
UX_STEP_CB(ux_display_continue_step,
           pb,
           (*g_validate_callback)(&G_dispatcher_context, true),
           {
               &C_icon_validate_14,
               "Continue",
           });

// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(&G_dispatcher_context, false),
           {
               &C_icon_crossmark,
               "Reject",
           });

/*
    STATEFUL STEPS
    These can only be used in the context of specific flows, as they access a common shared space
   for strings.
*/

// PATH/PUBKEY or PATH/ADDRESS

// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_ui_state.path_and_pubkey.bip32_path_str,
             });

// Step with title/text for pubkey
UX_STEP_NOCB(ux_display_pubkey_step,
             bnnn_paging,
             {
                 .title = "Public key",
                 .text = g_ui_state.path_and_pubkey.pubkey,
             });

// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_ui_state.path_and_address.address,
             });

// Step with icon and text with name of a wallet being registered
UX_STEP_NOCB(ux_display_wallet_header_name_step,
             pnn,
             {
                 &C_icon_wallet,
                 "Register wallet",
                 g_ui_state.wallet.wallet_name,
             });

// Step with description of a policy wallet
UX_STEP_NOCB(ux_display_wallet_policy_map_type_step,
             bnnn_paging,
             {
                 .title = "Policy map:",  // TODO: simplify for known multisig policies
                 .text = g_ui_state.wallet.policy_map,
             });

// Step with index and xpub of a cosigner of a policy_map wallet
UX_STEP_NOCB(ux_display_wallet_policy_map_cosigner_pubkey_step,
             bnnn_paging,
             {
                 .title = g_ui_state.cosigner_pubkey_and_index.signer_index,
                 .text = g_ui_state.cosigner_pubkey_and_index.pubkey,
             });

// Step with icon and text with name of a wallet being registered
UX_STEP_NOCB(ux_display_receive_in_wallet_step,
             pnn,
             {
                 &C_icon_wallet,
                 "Receive in:",
                 g_ui_state.wallet.wallet_name,
             });

// Step with title/text for address, used when showing a wallet receive address
UX_STEP_NOCB(ux_display_wallet_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_ui_state.wallet.address,
             });

// Step with icon and text with name of a wallet to spend from
UX_STEP_NOCB(ux_display_spend_from_wallet_step,
             pnn,
             {
                 &C_icon_wallet,
                 "Spend from:",
                 g_ui_state.wallet.wallet_name,
             });

// Step with warning icon and text explaining that there are external inputs
UX_STEP_NOCB(ux_display_warning_external_inputs_step,
             pnn,
             {
                 &C_icon_warning,
                 "There are",
                 "external inputs",
             });

// Step with eye icon and "Review" and the output index
UX_STEP_NOCB(ux_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 g_ui_state.validate_output.index,
             });

// Step with "Amount" and an output amount
UX_STEP_NOCB(ux_validate_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = g_ui_state.validate_output.amount,
             });

// Step with "Address" and a paginated address
UX_STEP_NOCB(ux_validate_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_ui_state.validate_output.address,
             });

UX_STEP_NOCB(ux_confirm_transaction_step, pnn, {&C_icon_eye, "Confirm", "transaction"});
UX_STEP_NOCB(ux_confirm_transaction_fees_step,
             bnnn_paging,
             {
                 .title = "Fees",
                 .text = g_ui_state.validate_transaction.fee,
             });
UX_STEP_CB(ux_accept_and_send_step,
           pbb,
           (*g_validate_callback)(&G_dispatcher_context, true),
           {&C_icon_validate_14, "Accept", "and send"});

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_sign_message_step,
             pnn,
             {
                 &C_icon_certificate,
                 "Sign",
                 "message",
             });

UX_STEP_NOCB(ux_message_sign_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_ui_state.path_and_hash.bip32_path_str,
             });

UX_STEP_NOCB(ux_message_hash_step,
             bnnn_paging,
             {
                 .title = "Message hash",
                 .text = g_ui_state.path_and_hash.hash_hex,
             });

UX_STEP_CB(ux_sign_message_accept,
           pbb,
           (*g_validate_callback)(&G_dispatcher_context, true),
           {&C_icon_validate_14, "Sign", "message"});

// FLOW to display BIP32 path and a message hash to sign:
// #1 screen: certificate icon + "Sign message"
// #2 screen: display BIP32 Path
// #3 screen: display message hash
// #4 screen: "Sign message" and approve button
// #5 screen: reject button
UX_FLOW(ux_sign_message_flow,
        &ux_sign_message_step,
        &ux_message_sign_display_path_step,
        &ux_message_hash_step,
        &ux_sign_message_accept,
        &ux_display_reject_step);

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

// FLOW to display BIP32 path and pubkey, for a non-standard path:
// #1 screen: warning icon + "The derivation path is unusual"
// #2 screen: crossmark icon + "Reject if not sure" (user can reject here)
// #3 screen: eye icon + "Confirm Pubkey"
// #4 screen: display BIP32 Path
// #5 screen: display pubkey
// #6 screen: approve button
// #7 screen: reject button
UX_FLOW(ux_display_pubkey_suspicious_flow,
        &ux_display_unusual_derivation_path_step,
        &ux_display_confirm_pubkey_step,
        &ux_display_path_step,
        &ux_display_reject_if_not_sure_step,
        &ux_display_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display a receive address, for a standard path:
// #1 screen: eye icon + "Confirm Address"
// #2 screen: display address
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_address_flow,
        &ux_display_confirm_address_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display a receive address, for a non-standard path:
// #1 screen: warning icon + "The derivation path is unusual"
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

// FLOW to warn the user if a change output has an unusual derivation path
// (e.g. account index or address index too large):
// #1 screen: warning icon + "The derivation path is unusual"
// #2 screen: display BIP32 Path
// #3 screen: crossmark icon + "Reject if not sure" (user can reject here)
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_unusual_derivation_path_flow,
        &ux_display_unusual_derivation_path_step,
        &ux_display_path_step,
        &ux_display_reject_if_not_sure_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display the header of a policy map wallet:
// #1 screen: eye icon + "Register wallet" and the wallet name
// #2 screen: display policy map (paginated)
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_policy_map_header_flow,
        &ux_display_wallet_header_name_step,
        &ux_display_wallet_policy_map_type_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display the header of a policy_map wallet:
// #1 screen: Cosigner index and pubkey (paginated)
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_policy_map_cosigner_pubkey_flow,
        &ux_display_wallet_policy_map_cosigner_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display the name and an address of a registered wallet:
// #1 screen: wallet name
// #2 screen: wallet address (paginated)
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_wallet_name_address_flow,
        &ux_display_receive_in_wallet_step,
        &ux_display_wallet_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display an address of a canonical wallet:
// #1 screen: wallet address (paginated)
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_canonical_wallet_address_flow,
        &ux_display_wallet_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to display a registered wallet and authorize spending:
// #1 screen: wallet name
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_wallet_for_spending_flow,
        &ux_display_spend_from_wallet_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// FLOW to warn about external inputs
// #1 screen: warning icon + "There are external inputs"
// #2 screen: crossmark icon + "Reject if not sure" (user can reject here)
// #3 screen: "continue" button
UX_FLOW(ux_display_warning_external_inputs_flow,
        &ux_display_warning_external_inputs_step,
        &ux_display_reject_if_not_sure_step,
        &ux_display_continue_step);

// FLOW to validate a single output
// #1 screen: eye icon + "Review" + index of output to validate
// #2 screen: output amount
// #3 screen: output address (paginated)
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_output_address_amount_flow,
        &ux_review_step,
        &ux_validate_amount_step,
        &ux_validate_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

// Finalize see the transaction fees and finally accept signing
// #1 screen: eye icon + "Confirm Transaction"
// #2 screen: fee amount
// #3 screen: "Accept and send", with approve button
// #4 screen: reject button
UX_FLOW(ux_accept_transaction_flow,
        &ux_confirm_transaction_step,
        &ux_confirm_transaction_fees_step,
        &ux_accept_and_send_step,
        &ux_display_reject_step);

// Division and modulus operators over uint64_t causes the inclusion of the __udivmoddi4 and other
// library functions that occupy more than 400 bytes. Since performance is not critical and division
// by 10 is sufficient, we avoid it with a binary search instead.
static uint64_t div10(uint64_t n) {
    if (n < 10) return 0;  // special case needed to make sure that n - 10 is safe

    // Since low, mid and high are always <= UINT64_MAX / 10, there is no risk of overflow
    uint64_t low = 0, high = UINT64_MAX / 10;

    while (true) {
        uint64_t mid = (low + high) / 2;

        // the result equals mid if and only if mid * 10 <= n < mid * 10 + 10
        // care is taken to make sure overflows and underflows are impossible
        if (mid * 10 > n - 10 && n >= mid * 10) {
            return mid;
        } else if (n < mid * 10) {
            high = mid - 1;
        } else /* n >= 10 * mid + 10 */ {
            low = mid + 1;
        }
    }
}

static uint64_t div100000000(uint64_t n) {
    uint64_t res = n;
    for (int i = 0; i < 8; i++) res = div10(res);
    return res;
}

static size_t n_digits(uint64_t number) {
    size_t count = 0;
    do {
        count++;

        // HACK: avoid __udivmoddi4
        // number /= 10;

        number = div10(number);
    } while (number != 0);
    return count;
}

// TODO: document and add unit tests
static void format_sats_amount(const char *coin_name,
                               uint64_t amount,
                               char out[static MAX_AMOUNT_LENGTH + 1]) {
    size_t coin_name_len = strlen(coin_name);
    strcpy(out, coin_name);
    out[coin_name_len] = ' ';

    char *amount_str = out + coin_name_len + 1;

    // HACK: avoid __udivmoddi4
    // uint64_t integral_part = amount / 100000000;
    // uint32_t fractional_part = (uint32_t) (amount % 100000000);
    uint64_t integral_part = div100000000(amount);
    uint32_t fractional_part = (uint32_t) (amount - integral_part * 100000000);

    // format the integral part, starting from the least significant digit
    size_t integral_part_digit_count = n_digits(integral_part);
    for (unsigned int i = 0; i < integral_part_digit_count; i++) {
        // HACK: avoid __udivmoddi4
        // amount_str[integral_part_digit_count - 1 - i] = '0' + (integral_part % 10);
        // integral_part /= 10;

        uint64_t tmp_quotient = div10(integral_part);
        char tmp_remainder = (char) (integral_part - 10 * tmp_quotient);
        amount_str[integral_part_digit_count - 1 - i] = '0' + tmp_remainder;
        integral_part = tmp_quotient;
    }

    if (fractional_part == 0) {
        amount_str[integral_part_digit_count] = '\0';
    } else {
        // format the fractional part (exactly 8 digits, possibly with trailing zeros)
        amount_str[integral_part_digit_count] = '.';
        char *fract_part_str = amount_str + integral_part_digit_count + 1;
        snprintf(fract_part_str, 8 + 1, "%08u", fractional_part);

        // drop trailing zeros
        for (int i = 7; i > 0 && fract_part_str[i] == '0'; i--) {
            fract_part_str[i] = '\0';
        }
    }
}

void ui_display_pubkey(dispatcher_context_t *context,
                       char *bip32_path_str,
                       bool is_path_suspicious,
                       char *pubkey,
                       action_validate_cb callback) {
    (void) (context);

    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    g_validate_callback = callback;

    if (!is_path_suspicious) {
        ux_flow_init(0, ux_display_pubkey_flow, NULL);
    } else {
        ux_flow_init(0, ux_display_pubkey_suspicious_flow, NULL);
    }
}

void ui_display_message_hash(dispatcher_context_t *context,
                             char *bip32_path_str,
                             char *message_hash,
                             action_validate_cb callback) {
    (void) (context);

    ui_path_and_hash_state_t *state = (ui_path_and_hash_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->hash_hex, message_hash, sizeof(state->hash_hex));

    g_validate_callback = callback;

    ux_flow_init(0, ux_sign_message_flow, NULL);
}

void ui_display_address(dispatcher_context_t *context,
                        char *address,
                        bool is_path_suspicious,
                        char *path_str,
                        action_validate_cb callback) {
    (void) (context);

    ui_path_and_address_state_t *state = (ui_path_and_address_state_t *) &g_ui_state;

    strncpy(state->address, address, sizeof(state->address));

    g_validate_callback = callback;

    if (!is_path_suspicious) {
        ux_flow_init(0, ux_display_address_flow, NULL);
    } else {
        strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
        ux_flow_init(0, ux_display_address_suspicious_flow, NULL);
    }
}

void ui_display_wallet_header(dispatcher_context_t *context,
                              policy_map_wallet_header_t *wallet_header,
                              action_validate_cb callback) {
    (void) (context);

    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_header->name, sizeof(wallet_header->name));
    strncpy(state->policy_map, wallet_header->policy_map, sizeof(wallet_header->policy_map));

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_policy_map_header_flow, NULL);
}

void ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *context,
                                           char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           bool is_internal,
                                           action_validate_cb callback) {
    (void) (context);
    (void) (n_keys);

    ui_cosigner_pubkey_and_index_state_t *state =
        (ui_cosigner_pubkey_and_index_state_t *) &g_ui_state;

    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (is_internal) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u <ours>",
                 cosigner_index + 1);
    } else {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u <theirs>",
                 cosigner_index + 1);
    }

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_policy_map_cosigner_pubkey_flow, NULL);
}

void ui_display_wallet_address(dispatcher_context_t *context,
                               char *wallet_name,
                               char *address,
                               action_validate_cb callback) {
    (void) (context);

    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->address, address, sizeof(state->address));
    g_validate_callback = callback;

    if (wallet_name == NULL) {
        ux_flow_init(0, ux_display_canonical_wallet_address_flow, NULL);
    } else {
        strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ux_flow_init(0, ux_display_wallet_name_address_flow, NULL);
    }
}

void ui_display_unusual_path(dispatcher_context_t *context,
                             char *bip32_path_str,
                             action_validate_cb callback) {
    (void) (context);

    ui_path_state_t *state = (ui_path_state_t *) &g_ui_state;

    g_validate_callback = callback;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    ux_flow_init(0, ux_display_unusual_derivation_path_flow, NULL);
}

void ui_authorize_wallet_spend(dispatcher_context_t *context,
                               char *wallet_name,
                               action_validate_cb callback) {
    (void) (context);

    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_wallet_for_spending_flow, NULL);
}

void ui_warn_external_inputs(dispatcher_context_t *context, action_validate_cb callback) {
    (void) (context);

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_warning_external_inputs_flow, NULL);
}

void ui_validate_output(dispatcher_context_t *context,
                        int index,
                        char *address,
                        char *coin_name,
                        uint64_t amount,
                        action_validate_cb callback) {
    (void) (context);

    ui_validate_output_state_t *state = (ui_validate_output_state_t *) &g_ui_state;

    snprintf(state->index, sizeof(state->index), "output #%d", index);
    strncpy(state->address, address, sizeof(state->address));
    format_sats_amount(coin_name, amount, state->amount);

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_output_address_amount_flow, NULL);
}

void ui_validate_transaction(dispatcher_context_t *context,
                             char *coin_name,
                             uint64_t fee,
                             action_validate_cb callback) {
    (void) (context);

    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    g_validate_callback = callback;

    format_sats_amount(coin_name, fee, state->fee);

    ux_flow_init(0, ux_accept_transaction_flow, NULL);
}
