#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset
#include <stdint.h>

#include "os.h"
#include "ux.h"

#include "./display.h"

#ifdef HAVE_BAGL
#define SET_UX_DIRTY true
#else
#define SET_UX_DIRTY false
#endif

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.

extern bool G_was_processing_screen_shown;

static bool g_ux_flow_ended;
static bool g_ux_flow_response;
static int g_current_streaming_index;

extern dispatcher_context_t G_dispatcher_context;

ui_state_t g_ui_state;

void send_deny_sw(dispatcher_context_t *dc) {
    SEND_SW(dc, SW_DENY);
}

void set_ux_flow_response(bool approved) {
    g_ux_flow_ended = true;
    g_ux_flow_response = approved;
}

uint8_t get_streaming_index(void) {
    return g_current_streaming_index;
}

void reset_streaming_index(void) {
    PRINTF("Reset streaming index\n");
    g_current_streaming_index = 0;
}

void increase_streaming_index(void) {
    PRINTF("Increase streaming index\n");
    g_current_streaming_index += 1;
}

void decrease_streaming_index(void) {
    PRINTF("Decrease streaming index\n");
    if (g_current_streaming_index > 0) {
        g_current_streaming_index -= 1;
    }
}

// Process UI events until the current flow terminates; does not handle any APDU exchange
// This method also sets the UI state as "dirty" according to the input parameter
// so that the dispatcher refreshes resets the UI at the end of the command handler.
// Returns true/false depending if the user accepted in the corresponding UX flow.
static bool io_ui_process(dispatcher_context_t *context, bool set_dirty) {
    G_was_processing_screen_shown = false;

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
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *) &g_ui_state;

    strncpy(state->bip32_path_str, bip32_path_str, sizeof(state->bip32_path_str));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (!is_path_suspicious) {
        ui_display_pubkey_flow();
    } else {
        ui_display_pubkey_suspicious_flow();
    }

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_path_and_message_content(dispatcher_context_t *context,
                                         const char *path_str,
                                         const char *message_content) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    strncpy(state->message, message_content, sizeof(state->message));

    ui_sign_message_content_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_message_path_hash_and_confirm(dispatcher_context_t *context,
                                              const char *path_str,
                                              const char *message_hash) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_path_and_message_state_t *state = (ui_path_and_message_state_t *) &g_ui_state;
    strncpy(state->bip32_path_str, path_str, sizeof(state->bip32_path_str));
    strncpy(state->message, message_hash, sizeof(state->message));

    ui_sign_message_path_hash_and_confirm_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_message_confirm(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    (void) context;
    ui_sign_message_confirm_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

    strncpy(state->wallet_name, wallet_header->name, sizeof(state->wallet_name));
    state->wallet_name[wallet_header->name_len] = 0;
    strncpy(state->descriptor_template, policy_descriptor, sizeof(state->descriptor_template));
    state->descriptor_template[wallet_header->descriptor_template_len] = 0;

    ui_display_register_wallet_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           key_type_e key_type) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    (void) (n_keys);

    ui_cosigner_pubkey_and_index_state_t *state =
        (ui_cosigner_pubkey_and_index_state_t *) &g_ui_state;

    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    if (key_type == PUBKEY_TYPE_INTERNAL) {
        snprintf(state->signer_index, sizeof(state->signer_index), "Key @%u, ours", cosigner_index);
    } else if (key_type == PUBKEY_TYPE_EXTERNAL) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, theirs",
                 cosigner_index);
    } else if (key_type == PUBKEY_TYPE_UNSPENDABLE) {
        snprintf(state->signer_index,
                 sizeof(state->signer_index),
                 "Key @%u, dummy",
                 cosigner_index);
    } else {
        LEDGER_ASSERT(false, "Unreachable code");
    }
    ui_display_policy_map_cosigner_pubkey_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    strncpy(state->address, address, sizeof(state->address));

    if (wallet_name == NULL) {
        ui_display_default_wallet_address_flow();
    } else {
        strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
        ui_display_receive_in_wallet_flow();
    }

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name) {
    ui_wallet_state_t *state = (ui_wallet_state_t *) &g_ui_state;

#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    ui_display_spend_from_wallet_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_warn_external_inputs(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_warning_external_inputs_flow();
    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_unverified_segwit_inputs_flows();
    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_nondefault_sighash_flow();
    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_transaction_prompt(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_display_transaction_prompt();
    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        int total_count,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

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

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_warn_high_fee(dispatcher_context_t *context) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_warn_high_fee_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}

bool ui_validate_transaction(dispatcher_context_t *context,
                             const char *coin_name,
                             uint64_t fee,
                             bool is_self_transfer) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_validate_transaction_state_t *state = (ui_validate_transaction_state_t *) &g_ui_state;

    format_sats_amount(coin_name, fee, state->fee);

    ui_accept_transaction_flow(is_self_transfer);

    return io_ui_process(context, SET_UX_DIRTY);
}

#ifdef HAVE_NBGL
bool ui_validate_transaction_simplified(dispatcher_context_t *context,
                                        const char *coin_name,
                                        const char *wallet_policy_name,
                                        uint64_t amount,
                                        const char *address_or_description,
                                        tx_ux_warning_t warnings,
                                        uint64_t fee) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    ui_validate_transaction_simplified_state_t *state =
        (ui_validate_transaction_simplified_state_t *) &g_ui_state;

    if (wallet_policy_name != NULL) {
        strncpy(state->wallet_policy_name, wallet_policy_name, sizeof(state->wallet_policy_name));
        state->has_wallet_policy = true;
    } else {
        memset(state->wallet_policy_name, 0, sizeof(state->wallet_policy_name));
        state->has_wallet_policy = false;
    }
    format_sats_amount(coin_name, amount, state->amount);
    strncpy(state->address_or_description,
            address_or_description,
            sizeof(state->address_or_description));
    state->warnings = warnings;
    format_sats_amount(coin_name, fee, state->fee);

    ui_accept_transaction_simplified_flow();

    return io_ui_process(context, SET_UX_DIRTY);
}
#endif

#ifdef HAVE_BAGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
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

void ui_pre_processing_message(void) {
    return;
}
#endif  // HAVE_BAGL

#ifdef HAVE_NBGL
bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    (void) context;
    ui_display_post_processing_confirm_wallet_registation(success);

    return true;
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    (void) context;
    ui_display_post_processing_confirm_transaction(success);

    return true;
}

bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
#ifdef HAVE_AUTOAPPROVE_FOR_PERF_TESTS
    return true;
#endif

    (void) context;
    ui_display_post_processing_confirm_message(success);

    return true;
}

void ui_pre_processing_message(void) {
    ui_set_display_prompt();
}
#endif  // HAVE_NBGL
