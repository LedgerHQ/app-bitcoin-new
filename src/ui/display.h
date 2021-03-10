#pragma once

#include <stdbool.h>  // bool

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display the derivation path and pubkey, and asks the confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 * TODO: document params
 */
int ui_display_pubkey(char *path, char *xpub, action_validate_cb callback);

// TODO: docs
int ui_display_address(char *address, bool is_path_suspicious, action_validate_cb callback);