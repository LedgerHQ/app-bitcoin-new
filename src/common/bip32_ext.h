#pragma once

#include "lib_standard_app/bip32.h"

/**
 * Maximum length of BIP32 path supported.
 * Note: BIP32 allows up to 256 derivation steps - but only 5 or 6 are used in most cases.
 */
#define MAX_BIP32_PATH_STEPS MAX_BIP32_PATH

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

#define MAX_BIP44_ACCOUNT_RECOMMENDED       100
#define MAX_BIP44_ADDRESS_INDEX_RECOMMENDED 50000
