#include <assert.h>

#include "ux.h"
#include "usbd_core.h"
#include "os_io_seproxyhal.h"

#include "handle_swap_sign_transaction.h"

#ifndef DISABLE_LEGACY_SUPPORT
#include "../legacy/btchip_display_variables.h"
#include "../legacy/btchip_public_ram_variables.h"
#endif

#include "../main.h"
#include "../globals.h"
#include "../swap/swap_globals.h"
#include "../common/read.h"

bool copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params) {
    char destination_address[65];
    uint8_t amount[8];
    uint8_t fees[8];

    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with btc-app globals
    memset(destination_address, 0, sizeof(destination_address));
    memset(amount, 0, sizeof(amount));
    memset(fees, 0, sizeof(fees));
    strncpy(destination_address,
            sign_transaction_params->destination_address,
            sizeof(destination_address) - 1);

    // sanity checks
    if ((destination_address[sizeof(destination_address) - 1] != '\0') ||
        (sign_transaction_params->amount_length > 8) ||
        (sign_transaction_params->fee_amount_length > 8)) {
        return false;
    }

    // store amount as big endian in 8 bytes, so the passed data should be aligned to right
    // input {0xEE, 0x00, 0xFF} should be stored like {0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x00,
    // 0xFF}
    memcpy(amount + 8 - sign_transaction_params->amount_length,
           sign_transaction_params->amount,
           sign_transaction_params->amount_length);
    memcpy(fees + 8 - sign_transaction_params->fee_amount_length,
           sign_transaction_params->fee_amount,
           sign_transaction_params->fee_amount_length);

#ifndef DISABLE_LEGACY_SUPPORT
    // fill vars.swap_data, used by the legacy app only
    _Static_assert(sizeof(vars.swap_data.destination_address) == sizeof(destination_address),
                   "Wrong size");
    _Static_assert(sizeof(vars.swap_data.amount) == 8, "Wrong size");
    _Static_assert(sizeof(vars.swap_data.fees) == 8, "Wrong size");
    memcpy(vars.swap_data.destination_address,
           destination_address,
           sizeof(vars.swap_data.destination_address));
    memcpy(vars.swap_data.amount, amount, 8);
    memcpy(vars.swap_data.fees, fees, 8);
#endif

    G_swap_state.amount = read_u64_be(amount, 0);
    G_swap_state.fees = read_u64_be(fees, 0);
    memcpy(G_swap_state.destination_address,
           destination_address,
           sizeof(G_swap_state.destination_address));
    return true;
}

void handle_swap_sign_transaction(btchip_altcoin_config_t* config) {
    G_coin_config = config;
#ifndef DISABLE_LEGACY_SUPPORT
    // We make sure to initialize the app in "legacy" mode, otherwise the state
    // would be wiped in app_main
    memset(&btchip_context_D, 0, sizeof(btchip_context_D));
    btchip_context_init();
    G_app_mode = APP_MODE_LEGACY;
#else
    G_app_mode = APP_MODE_UNINITIALIZED;
#endif
    G_swap_state.called_from_swap = 1;

    io_seproxyhal_init();
    UX_INIT();
    ux_stack_push();

    USB_power(0);
    USB_power(1);
    // ui_idle();
    PRINTF("USB power ON/OFF\n");
#ifdef TARGET_NANOX
    // grab the current plane mode setting
    G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX
#ifdef HAVE_BLE
    BLE_power(0, NULL);
    BLE_power(1, "Nano X");
#endif  // HAVE_BLE
    app_main();
}