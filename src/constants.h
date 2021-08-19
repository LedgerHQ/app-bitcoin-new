#pragma once

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP_LEGACY 0xE0

/**
 * Instruction class of the Bitcoin application.
 */
#define CLA_APP 0xE1

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum length of a serialized address (in characters).
 */
#define MAX_ADDRESS_LENGTH_STR 74  // segwit addresses can reach 74 characters

/**
 * Maximum transaction length (bytes).
 */
#define MAX_TRANSACTION_LEN 510

/**
 * Maximum DER-encoded signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * Exponent used to convert mBTC to BTC unit (N BTC = N * 10^3 mBTC).
 */
#define EXPONENT_SMALLEST_UNIT 3

/**
 * Maximum scriptPubKey length for an input that we can sign.
 */
#define MAX_PREVOUT_SCRIPTPUBKEY_LEN 34  // P2WSH's scriptPubKeys are the longest supported

/**
 * Maximum length of a wallet registered into the device (characters), excluding terminating NULL.
 */
#define MAX_WALLET_NAME_LENGTH 16

/**
 * Maximum length (characters) of a base58check-encoded serialized extended pubkey.
 */
#define MAX_SERIALIZED_PUBKEY_LENGTH 113

// SIGHASH flags
#define SIGHASH_ALL          0x00000001
#define SIGHASH_NONE         0x00000002
#define SIGHASH_SINGLE       0x00000003
#define SIGHASH_ANYONECANPAY 0x00000080
