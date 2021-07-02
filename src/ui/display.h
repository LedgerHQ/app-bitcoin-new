#pragma once

#include <stdbool.h>  // bool
#include "../boilerplate/dispatcher.h"

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
int ui_display_pubkey(dispatcher_context_t *dispatcher_context,
                      char *path,
                      char *xpub,
                      action_validate_cb callback);

// TODO: docs
int ui_display_address(dispatcher_context_t *dispatcher_context,
                       char *address,
                       bool is_path_suspicious,
                       char *path_str,
                       action_validate_cb callback);

int ui_display_multisig_header(dispatcher_context_t *dispatcher_context,
                               char *wallet_name,
                               uint8_t threshold,
                               uint8_t n_keys,
                               action_validate_cb callback);

int ui_display_multisig_cosigner_pubkey(dispatcher_context_t *dispatcher_context,
                                        char *pubkey,
                                        uint8_t cosigner_index,
                                        uint8_t n_keys,
                                        action_validate_cb callback);

int ui_display_wallet_address(dispatcher_context_t *context,
                              char *wallet_name,
                              char *address,
                              action_validate_cb callback);

int ui_authorize_wallet_spend(dispatcher_context_t
                              *context,
                              char
                              *wallet_name,
                              action_validate_cb callback);
