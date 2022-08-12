#pragma once

#include "../boilerplate/dispatcher.h"
#include "../constants.h"
#include "../common/merkle.h"
#include "../common/wallet.h"
#include "../crypto.h"

#define MAX_N_INPUTS_CAN_SIGN 512

void handler_sign_psbt(dispatcher_context_t *dispatcher_context, uint8_t p2);
