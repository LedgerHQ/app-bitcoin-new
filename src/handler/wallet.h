#pragma once

#include <stdint.h>

#include "common/buffer.h"
#include "../constants.h"

#include "os.h"
#include "cx.h"

#define WALLET_TYPE_MULTISIG 1

#define MAX_MULTISIG_COSIGNERS 15

// Enough to store "sh(wsh(sortedmulti(15,\t0,\t1,\t2,\t3,\t4,\t5,\t6,\t7,\t8,\t9,\t10,\t11,\t12,\t13,\t14)))"
#define MAX_MULTISIG_POLICY_MAP_LENGTH 74

// The string describing a pubkey can contain:
// (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 3*12 = 46 bytes)
// the xpub itself (up to 113 characters)
// Therefore, the total length of the key info string is 159 bytes.
#define MAX_MULTISIG_SIGNER_INFO_LEN (46 + MAX_SERIALIZED_PUBKEY_LENGTH)

// Currently only multisig is supported
#define MAX_POLICY_MAP_LEN MAX_MULTISIG_POLICY_MAP_LENGTH

typedef struct {
    uint32_t master_key_derivation[MAX_BIP32_PATH_STEPS];
    uint8_t master_key_derivation_len;
    uint8_t master_key_fingerprint[4];
    uint8_t has_key_origin;
    uint8_t has_wildcard; // true iff the keys ends with the /** wildcard
    char ext_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} policy_map_key_info_t;


typedef struct {
    uint8_t address_type;
    uint8_t threshold;
    uint8_t n_keys;
    uint8_t sorted; // 0 for multi, 1 for sortedmulti
} multisig_wallet_policy_t;


typedef struct {
    uint8_t type; // Currently the only supported value is WALLET_TYPE_MULTISIG
    uint8_t name_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];

    /* The remaining fields are specific to multisig wallets */
    multisig_wallet_policy_t multisig_policy;
    uint8_t keys_info_merkle_root[20];        // root of the Merkle tree of the keys information
} multisig_wallet_header_t;



/**
 * TODO: docs 
 */
int read_wallet_header(buffer_t *buffer, multisig_wallet_header_t *header);


/**
 * TODO: docs 
 */
void hash_update_append_wallet_header(cx_hash_t *hash_context, multisig_wallet_header_t *header);


/**
 * Parses a policy map for the supported wallet types, filling the 'out' buffer.
 * Fails if any parsing error occurs, or if the buffer is not exhausted exactly.
 * Returns -1 on failure
 */
int buffer_read_multisig_policy_map(buffer_t *buffer, multisig_wallet_policy_t *out);

/**
 * 
 * Parses a string representing the key information for a policy map wallet (multisig).
 * The string is compatible with the output descriptor format, except that the pubkey must _not_ have derivation steps
 * (the key origin info, if present, does have derivation steps from the master key fingerprint).
 * The serialized base58check-encoded pubkey is _not_ validated.
 * 
 * For example: "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out);


/**
 * TODO: docs
 */
void get_policy_wallet_id(multisig_wallet_header_t *wallet_header,
                          uint16_t policy_map_len,
                          const char policy_map[],
                          uint16_t n_keys,
                          const uint8_t keys_info_merkle_root[static 20],
                          uint8_t out[static 32]);
