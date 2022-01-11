#pragma once

#include <stdbool.h>  // bool
#include "../boilerplate/dispatcher.h"

#include "../common/wallet.h"

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(dispatcher_context_t *dispatcher_context, bool);

/**
 * Display the derivation path and pubkey, and asks the confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 * TODO: document params
 */
void ui_display_pubkey(dispatcher_context_t *dispatcher_context,
                       char *bip32_path_str,
                       bool is_path_suspicious,
                       char *pubkey,
                       action_validate_cb callback);

// TODO: docs
void ui_display_message_hash(dispatcher_context_t *context,
                             char *bip32_path_str,
                             char *message_hash,
                             action_validate_cb callback);

void ui_display_address(dispatcher_context_t *dispatcher_context,
                        char *address,
                        bool is_path_suspicious,
                        char *bip32_path_str,
                        action_validate_cb callback);

void ui_display_wallet_header(dispatcher_context_t *context,
                              policy_map_wallet_header_t *wallet_header,
                              action_validate_cb callback);

void ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *dispatcher_context,
                                           char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           bool is_internal,
                                           action_validate_cb callback);

void ui_display_wallet_address(dispatcher_context_t *context,
                               char *wallet_name,
                               char *address,
                               action_validate_cb callback);

void ui_display_unusual_path(dispatcher_context_t *context,
                             char *bip32_path_str,
                             action_validate_cb callback);

void ui_authorize_wallet_spend(dispatcher_context_t *context,
                               char *wallet_name,
                               action_validate_cb callback);

void ui_warn_external_inputs(dispatcher_context_t *context, action_validate_cb callback);

void ui_validate_output(dispatcher_context_t *context,
                        int index,
                        char *address,
                        char *coin_name,
                        uint64_t amount,
                        action_validate_cb callback);

void ui_validate_transaction(dispatcher_context_t *context,
                             char *coin_name,
                             uint64_t fee,
                             action_validate_cb callback);
