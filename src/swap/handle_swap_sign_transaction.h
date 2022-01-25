#pragma once

#include "swap_lib_calls.h"
#include "../legacy/include/btchip_context.h"

bool copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params);

void handle_swap_sign_transaction(btchip_altcoin_config_t* config);
