#pragma once

#define APP_MODE_UNINITIALIZED 0  // state before any APDU is executed
#define APP_MODE_LEGACY        1  // state when the app is running legacy APDUs
#define APP_MODE_NEW           2  // state when the app is running new APDUs

/**
 * Keeps track whether the app is running in "legacy" or "new" mode.
 */
extern uint8_t G_app_mode;