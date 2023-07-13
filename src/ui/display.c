#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset
#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "./display.h"

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.

static bool g_ux_flow_ended;
static bool g_ux_flow_response;

extern dispatcher_context_t G_dispatcher_context;

ui_state_t g_ui_state;

void send_deny_sw(dispatcher_context_t *dc) {
    SEND_SW(dc, SW_DENY);
}

void set_ux_flow_response(bool approved) {
    g_ux_flow_ended = true;
    g_ux_flow_response = approved;
}

// Process UI events until the current flow terminates; does not handle any APDU exchange
// This method also sets the UI state as "dirty" according to the input parameter
// so that the dispatcher refreshes resets the UI at the end of the command handler.
// Returns true/false depending if the user accepted in the corresponding UX flow.
static bool io_ui_process(dispatcher_context_t *context, bool set_dirty) {
    g_ux_flow_ended = false;

    if (set_dirty) {
        context->set_ui_dirty();
    }

    // We are not waiting for the client's input, nor we are doing computations on the device
    io_clear_processing_timeout();

    io_seproxyhal_general_status();
    do {
        io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer, sizeof(G_io_seproxyhal_spi_buffer), 0);
        io_seproxyhal_handle_event();
        io_seproxyhal_general_status();
    } while (io_seproxyhal_spi_is_status_sent() && !g_ux_flow_ended);

    // We're back at work, we want to show the "Processing..." screen when appropriate
    io_start_processing_timeout();

    return g_ux_flow_response;
}

bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       bool is_path_suspicious,
                       const char *pubkey) {
    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (!is_path_suspicious) {
        ui_display_pubkey_flow();
    } else {
        ui_display_pubkey_suspicious_flow();
    }

    return io_ui_process(context, true);
}

bool ui_display_message_hash(dispatcher_context_t *context,
                             const char *bip32_path_str,
                             const char *message_hash) {
    ui_path_and_hash_state_t *state = (ui_path_and_hash_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->hash_hex, message_hash, sizeof(state->hash_hex));

    ui_sign_message_flow();

    return io_ui_process(context, true);
}

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_header->name, sizeof(state->wallet_name));
    state->wallet_name[wallet_header->name_len] = 0;
    strncpy(state->descriptor_template, policy_descriptor, sizeof(state->descriptor_template));
    state->descriptor_template[wallet_header->descriptor_template_len] = 0;

    ui_display_register_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           bool is_internal) {
    (void) (n_keys);

    ui_cosigner_pubkey_and_index_state_t *state =
        (ui_cosigner_pubkey_and_index_state_t *) &g_ui_state;

    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (is_internal) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u <ours>",
                 cosigner_index);
    } else {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u <theirs>",
                 cosigner_index);
    }
    ui_display_policy_map_cosigner_pubkey_flow();

    return io_ui_process(context, true);
}

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->address, address, sizeof(state->address));

    if (wallet_name == NULL) {
        ui_display_default_wallet_address_flow();
    } else {
        strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ui_display_receive_in_wallet_flow();
    }

    return io_ui_process(context, true);
}

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    ui_display_spend_from_wallet_flow();

    return io_ui_process(context, true);
}

bool ui_warn_external_inputs(dispatcher_context_t *context) {
    ui_display_warning_external_inputs_flow();
    return io_ui_process(context, true);
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
    ui_display_unverified_segwit_inputs_flows();
    return io_ui_process(context, true);
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context) {
    ui_display_nondefault_sighash_flow();
    return io_ui_process(context, true);
}

bool ui_transaction_prompt(dispatcher_context_t *context, const int external_outputs_total_count) {
    ui_display_transaction_prompt(external_outputs_total_count);
    return io_ui_process(context, true);
}

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        int total_count,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount) {
    ui_validate_output_state_t *state = (ui_validate_output_state_t *) &g_ui_state;

    strncpy(state->address_or_description,
            address_or_description,
            sizeof(state->address_or_description));
    format_sats_amount(coin_name, amount, state->amount);

    if (total_count == 1) {
        ui_display_output_address_amount_no_index_flow(index);
    } else {
        ui_display_output_address_amount_flow(index);
    }

    return io_ui_process(context, true);
}

bool ui_validate_transaction(dispatcher_context_t *context,
                             const char *coin_name,
                             uint64_t fee,
                             bool is_self_transfer) {
    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(coin_name, fee, state->fee);

    ui_accept_transaction_flow(is_self_transfer);

    return io_ui_process(context, true);
}

#ifdef HAVE_BAGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    (void) success;
    return true;
}

#endif  // HAVE_BAGL

#ifdef HAVE_NBGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_wallet_registation(success);

    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_wallet_spend(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    ui_display_post_processing_confirm_transaction(success);

    return io_ui_process(context, success);
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    (void) context;
    ui_display_post_processing_confirm_message(success);

    return true;
}
#endif  // HAVE_NBGL
