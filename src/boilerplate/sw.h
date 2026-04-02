#pragma once

/* SDK headers */
#include "status_words.h"

/**
 * Status word for success.
 */
#define SW_OK 0x9000
_Static_assert(SW_OK == SWO_SUCCESS, "Status word value does not match with the SDK one");

/**
 * Status word for command not valid for security reasons (for example: device needs to be unlocked
 * with PIN).
 */
#define SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
_Static_assert(SW_SECURITY_STATUS_NOT_SATISFIED == SWO_SECURITY_CONDITION_NOT_SATISFIED,
               "Status word value does not match with the SDK one");

/**
 * Status word for denied by user.
 */
#define SW_DENY 0x6985
_Static_assert(SW_DENY == SWO_CONDITIONS_NOT_SATISFIED,
               "Status word value does not match with the SDK one");

/**
 * Status word for data.
 */
#define SW_INCORRECT_DATA 0x6A80
_Static_assert(SW_INCORRECT_DATA == SWO_INCORRECT_DATA,
               "Status word value does not match with the SDK one");

/**
 * Status word for request not currently supported (but not otherwise wrong).
 */
#define SW_NOT_SUPPORTED 0x6A82

/**
 * Status word for incorrect P1 or P2.
 */
#define SW_WRONG_P1P2 0x6A86
_Static_assert(SW_WRONG_P1P2 == SWO_INCORRECT_P1_P2,
               "Status word value does not match with the SDK one");

/**
 * Status word for either wrong Lc or length of APDU command less than 5.
 */
#define SW_WRONG_DATA_LENGTH 0x6A87
_Static_assert(SW_WRONG_DATA_LENGTH == SWO_WRONG_DATA_LENGTH,
               "Status word value does not match with the SDK one");

/**
 * Status word for fail in Swap
 */
#define SW_FAIL_SWAP 0x6B00

/**
 * Status word for unknown command with this INS.
 */
#define SW_INS_NOT_SUPPORTED 0x6D00
_Static_assert(SW_INS_NOT_SUPPORTED == SWO_INVALID_INS,
               "Status word value does not match with the SDK one");

/**
 * Status word for instruction class is different than CLA.
 */
#define SW_CLA_NOT_SUPPORTED 0x6E00
_Static_assert(SW_CLA_NOT_SUPPORTED == SWO_INVALID_CLA,
               "Status word value does not match with the SDK one");

/**
 * Status word for wrong response length (buffer too small or too big).
 */
#define SW_WRONG_RESPONSE_LENGTH 0xB000

/**
 * Status word for bad state.
 */
#define SW_BAD_STATE 0xB007

/**
 * Status word for signature fail.
 */
#define SW_SIGNATURE_FAIL 0xB008

/**
 * Status word for interrupted execution.
 */
#define SW_INTERRUPTED_EXECUTION 0xE000
