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
 * TODO: docs
 */
bool ui_display_pubkey(dispatcher_context_t *context,
                       const char *bip32_path_str,
                       bool is_path_suspicious,
                       const char *pubkey);

// TODO: docs
bool ui_display_message_hash(dispatcher_context_t *context,
                             const char *bip32_path_str,
                             const char *message_hash);

bool ui_display_address(dispatcher_context_t *dispatcher_context,
                        const char *address,
                        bool is_path_suspicious,
                        const char *bip32_path_str);

bool ui_display_register_wallet(dispatcher_context_t *context,
                                const policy_map_wallet_header_t *wallet_header,
                                const char *policy_descriptor);

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *dispatcher_context,
                                           const char *pubkey,
                                           uint8_t cosigner_index,
                                           uint8_t n_keys,
                                           bool is_internal);

bool ui_display_wallet_address(dispatcher_context_t *context,
                               const char *wallet_name,
                               const char *address);

bool ui_display_unusual_path(dispatcher_context_t *context, const char *bip32_path_str);

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name);

bool ui_warn_external_inputs(dispatcher_context_t *context);

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context);

bool ui_warn_nondefault_sighash(dispatcher_context_t *context);

bool ui_validate_output(dispatcher_context_t *context,
                        int index,
                        const char *address_or_description,
                        const char *coin_name,
                        uint64_t amount);

bool ui_validate_transaction(dispatcher_context_t *context, const char *coin_name, uint64_t fee);
