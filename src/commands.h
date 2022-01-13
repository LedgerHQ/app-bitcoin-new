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

/**
 * Union of the global state for all the commands.
 */
typedef union {
    get_master_fingerprint_t get_master_fingerprint;
    get_extended_pubkey_state_t get_extended_pubkey_state;
    register_wallet_state_t register_wallet_state;
    get_wallet_address_state_t get_wallet_address_state;
    sign_psbt_state_t sign_psbt_state;
    sign_message_state_t sign_message_state;
} command_state_t;

/**
 * Since only one command can execute at the same time, we share the same global space
 * for the command state of all the commands.
 **/
extern command_state_t G_command_state;
