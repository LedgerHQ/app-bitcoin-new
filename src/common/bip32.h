#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

/**
 * Maximum length of BIP32 path supported.
 * Note: BIP32 allows up to 256 derivation steps - but only 5 or 6 are used in most cases.
 */
#define MAX_BIP32_PATH_STEPS 8

/**
 * Maximum length of a string representing a BIP32 derivation path.
 * Each step is up to 11 characters (10 decimal digits, plus the "hardened" symbol),
 * and there is 1 separator before each step.
 */
#define MAX_SERIALIZED_BIP32_PATH_LENGTH (12 * MAX_BIP32_PATH_STEPS)

/**
 * Index of first hardened child according to BIP32; it can also be used as the bitmask for hardened
 * children.
 */
#define BIP32_FIRST_HARDENED_CHILD 0x80000000

#define BIP44_PURPOSE_OFFSET                0
#define BIP44_COIN_TYPE_OFFSET              1
#define BIP44_ACCOUNT_OFFSET                2
#define BIP44_CHANGE_OFFSET                 3
#define BIP44_ADDRESS_INDEX_OFFSET          4
#define MAX_BIP44_ACCOUNT_RECOMMENDED       100
#define MAX_BIP44_ADDRESS_INDEX_RECOMMENDED 50000

// Address types
// Legacy address. P2PKH for single sig, P2SH for scripts.
#define ADDRESS_TYPE_LEGACY 1
// Native segwit. P2WPKH for single sig, P2WPSH for scripts.
#define ADDRESS_TYPE_WIT 2
// Nested segwit. P2SH-P2WPKH for single sig, P2SH-P2WPSH for scripts.
#define ADDRESS_TYPE_SH_WIT 3
// Taproot P2TR
#define ADDRESS_TYPE_TR 4

/**
 * Read BIP32 path from byte buffer.
 *
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of input byte buffer.
 * @param[out] out
 *   Pointer to output 32-bit integer buffer.
 * @param[in]  out_len
 *   Number of BIP32 paths read in the output buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool bip32_path_read(const uint8_t *in, size_t in_len, uint32_t *out, size_t out_len);

/**
 * Format BIP32 path as string.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit integer input buffer.
 * @param[in]  bip32_path_len
 *   Maximum number of BIP32 paths in the input buffer.
 * @param[out] out string
 *   Pointer to output string.
 * @param[in]  out_len
 *   Length of the output string.
 *
 * @return true if success, false otherwise.
 *
 */
bool bip32_path_format(const uint32_t *bip32_path,
                       size_t bip32_path_len,
                       char *out,
                       size_t out_len);

/**
 * Verifies if a given path is standard according to BIP44 or derived standards, and it is
 * reasonable to export its pubkey. Should not export paths that are too short to specify the coin
 * type (it would expose other coins' keys), but also not deeper than the standard account number
 * (third level of derivation), since no standard currently defines deeper hardened derivations.
 *
 * Returns false if any of the following conditions is not satisfied by the given bip32_path:
 * - the bip32_path has 2 or 3 steps;
 * - purpose, coin_type and account_number (if given) are hardened;
 * - purpose is not hardened, or it does not match expected_purpose;
 * - coin_type is in the expected_coin_types array (if given);
 * - account_number (if given) at most MAX_BIP44_ACCOUNT_RECOMMENDED.
 *
 * @param[in]  bip32_path
 *   Pointer to 32-bit integer input buffer.
 * @param[in]  bip32_path_len
 *   Maximum number of BIP32 paths in the input buffer.
 * @param[in]  expected_purpose
 *   The purpose that should be in the derivation (e.g. 44 for BIP44).
 * @param[in]  expected_coin_types
 *   Pointer to an array with the coin types that are considered acceptable. The
 *   elements of the array should be given as simple numbers (not their hardened version);
 *   for example, the coin type for Bitcoin is 0.
 *   Ignored if expected_coin_types_len is 0; in that case, it is only checked
 *   that the coin_type is hardened, as expected in the standard.
 * @param[in]  expected_coin_types_len
 *   The length of expected_coin_types.
 *
 * @return true if the given address is standard, false otherwise.
 *
 */
bool is_pubkey_path_standard(const uint32_t *bip32_path,
                             size_t bip32_path_len,
                             uint32_t expected_purpose,
                             const uint32_t expected_coin_types[],
                             size_t expected_coin_types_len);
