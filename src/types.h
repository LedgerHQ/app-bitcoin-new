#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "constants.h"
#include "transaction/types.h"
#include "common/bip32.h"
#include "commands.h"

/**
 * Enumeration for the status of IO.
 */
typedef enum {
    READY,     /// ready for new event
    RECEIVED,  /// data received
    WAITING    /// waiting
} io_state_e;

/**
 * Structure with fields of APDU command.
 */
typedef struct {
    uint8_t cla;    /// Instruction class
    command_e ins;  /// Instruction code
    uint8_t p1;     /// Instruction parameter 1
    uint8_t p2;     /// Instruction parameter 2
    uint8_t lc;     /// Lenght of command data
    uint8_t *data;  /// Command data
} command_t;

/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,     /// confirm address derived from public key
    CONFIRM_TRANSACTION  /// confirm transaction information
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[64];  /// x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[32];      /// for public key derivation
} pubkey_ctx_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    uint8_t raw_tx[MAX_TRANSACTION_LEN];  /// raw transaction serialized
    size_t raw_tx_len;                    /// length of raw transaction
    transaction_t transaction;            /// structured transaction
    uint8_t m_hash[32];                   /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];   /// transaction signature encoded in DER
    uint8_t signature_len;                /// length of transaction signature
    uint8_t v;                            /// parity of y-coordinate of R in ECDSA signature
} transaction_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;       /// public key context
        transaction_ctx_t tx_info;  /// transaction context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// lenght of BIP32 path
} global_ctx_t;
