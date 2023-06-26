#include <assert.h>

#include "ux.h"
#include "usbd_core.h"
#include "os_io_seproxyhal.h"
#include "os.h"

#include "handle_swap_sign_transaction.h"

#include "../globals.h"
#include "../swap/swap_globals.h"
#include "../common/read.h"

// Save the BSS address where we will write the return value when finished
static uint8_t* G_swap_sign_return_value_address;

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

    os_explicit_zero_BSS_segment();
    G_swap_sign_return_value_address = &sign_transaction_params->result;

    G_swap_state.amount = read_u64_be(amount, 0);
    G_swap_state.fees = read_u64_be(fees, 0);
    memcpy(G_swap_state.destination_address,
           destination_address,
           sizeof(G_swap_state.destination_address));
    return true;
}

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success) {
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}
