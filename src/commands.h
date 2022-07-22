#pragma once

#include "boilerplate/dispatcher.h"
#include "constants.h"
#include "handler/get_master_fingerprint.h"
#include "handler/get_extended_pubkey.h"
#include "handler/get_wallet_address.h"
#include "handler/register_wallet.h"
#include "handler/sign_psbt.h"
#include "handler/sign_message.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_EXTENDED_PUBKEY = 0x00,
    REGISTER_WALLET = 0x02,
    GET_WALLET_ADDRESS = 0x03,
    SIGN_PSBT = 0x04,
    GET_MASTER_FINGERPRINT = 0x05,
    SIGN_MESSAGE = 0x10,
} command_e;
