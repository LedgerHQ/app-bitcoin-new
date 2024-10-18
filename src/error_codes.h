#pragma once

/**
 * Wallet Policies
 */

// TODO

/**
 * SIGN_PSBT
 */

// TODO

/**
 * Swap
 */

// For swap error codes, the first byte is standardized across apps.
// Refer to the documentation of app-exchange.

// Internal application error, forward to the firmware team for analysis.
#define EC_SWAP_ERROR_INTERNAL 0x0000

// The amount does not match the one validated in Exchange.
#define EC_SWAP_ERROR_WRONG_AMOUNT 0x0100

// The destination address does not match the one validated in Exchange.
#define EC_SWAP_ERROR_WRONG_DESTINATION 0x0200

// The fees are different from what was validated in Exchange.
#define EC_SWAP_ERROR_WRONG_FEES 0x0300

// The method used is invalid in Exchange context.
#define EC_SWAP_ERROR_WRONG_METHOD 0x0400
// Only default wallet policies can be used in swaps.
#define EC_SWAP_ERROR_WRONG_METHOD_NONDEFAULT_POLICY 0x0401
// No external inputs allowed in swap transactions.
#define EC_SWAP_ERROR_WRONG_METHOD_EXTERNAL_INPUTS 0x0402
// Segwit transaction in swap must have the non-witness UTXO in the PSBT.
#define EC_SWAP_ERROR_WRONG_METHOD_MISSING_NONWITNESSUTXO 0x0403
// Standard swap transaction must have exactly 1 external output.
#define EC_SWAP_ERROR_WRONG_METHOD_WRONG_N_OF_OUTPUTS 0x0404
// Invalid or unsupported script for external output.
#define EC_SWAP_ERROR_WRONG_METHOD_WRONG_UNSUPPORTED_OUTPUT 0x0405

// The mode used for the cross-chain hash validation is not supported.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_MODE 0x0500

// The method used is invalid in cross-chain Exchange context.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD 0x0600
// The first output must be OP_RETURN <data> for a cross-chain swap.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_INVALID_FIRST_OUTPUT 0x0601
// OP_RETURN with non-zero value is not supported.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_METHOD_NONZERO_AMOUNT 0x0602

// The hash for the cross-chain transaction does not match the validated value.
#define EC_SWAP_ERROR_CROSSCHAIN_WRONG_HASH 0x0700

// A generic or unspecified error not covered by the specific error codes above. Refer to the
// remaining bytes for further details on the error.
#define EC_SWAP_ERROR_GENERIC 0xFF00

// Unknown swap mode.
#define EC_SWAP_ERROR_GENERIC_UNKNOWN_MODE 0xFF01

// handle_swap_sign_transaction.c::copy_transaction_parameters failed.
#define EC_SWAP_ERROR_GENERIC_COPY_TRANSACTION_PARAMETERS_FAILED 0xFF02
