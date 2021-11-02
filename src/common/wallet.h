#pragma once

#include <stdint.h>

#include "common/bip32.h"
#include "common/buffer.h"
#include "../constants.h"

#ifndef SKIP_FOR_CMOCKA
#include "../context.h"
#include "os.h"
#include "cx.h"
#endif

#define WALLET_TYPE_POLICY_MAP 1

/**
 * Maximum supported number of keys for a policy map.
 */
#define MAX_POLICY_MAP_COSIGNERS 5

/**
 * Maximum supported number of keys for a policy map.
 */
#define MAX_POLICY_MAP_KEYS 5

// The string describing a pubkey can contain:
// - (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 3*12 = 46 bytes)
// - the xpub itself (up to 113 characters)
// - optional, the "/**" suffix.
// Therefore, the total length of the key info string is at most 162 bytes.
#define MAX_POLICY_KEY_INFO_LEN (46 + MAX_SERIALIZED_PUBKEY_LENGTH + 3)

// Enough to store "sh(wsh(sortedmulti(15,@0,@1,@2,@3,@4,@5,@6,@7,@8,@9,@10,@11,@12,@13,@14)))"
#define MAX_POLICY_MAP_STR_LENGTH 74

#define MAX_POLICY_MAP_NAME_LENGTH 16

// at most 126 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_POLICY_MAP_NAME_LENGTH bytes)
// policy length (1 byte)
// policy (max MAX_POLICY_MAP_STR_LENGTH bytes)
// n_keys (1 byte)
// keys_merkle_root (32 bytes)
#define MAX_POLICY_MAP_SERIALIZED_LENGTH \
    (1 + MAX_POLICY_MAP_NAME_LENGTH + 1 + MAX_POLICY_MAP_STR_LENGTH + 32)

// Maximum size of a parsed policy map in memory
#define MAX_POLICY_MAP_BYTES 128

// Currently only multisig is supported
#define MAX_POLICY_MAP_LEN MAX_MULTISIG_POLICY_MAP_LENGTH

typedef struct {
    uint32_t master_key_derivation[MAX_BIP32_PATH_STEPS];
    uint8_t master_key_fingerprint[4];
    uint8_t master_key_derivation_len;
    uint8_t has_key_origin;
    uint8_t has_wildcard;  // true iff the keys ends with the /** wildcard
    char ext_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} policy_map_key_info_t;

typedef struct {
    uint8_t type;  // Currently the only supported value is WALLET_TYPE_POLICY_MAP
    uint8_t name_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];
    uint16_t policy_map_len;
    char policy_map[MAX_POLICY_MAP_STR_LENGTH];
    size_t n_keys;
    uint8_t keys_info_merkle_root[32];  // root of the Merkle tree of the keys information
} policy_map_wallet_header_t;

typedef enum {
    TOKEN_SH,
    TOKEN_WSH,
    // TOKEN_PK,       // disabled, but it will be needed for taproot
    TOKEN_PKH,
    TOKEN_WPKH,
    // TOKEN_COMBO     // disabled, does not mix well with the script policy language
    TOKEN_MULTI,
    TOKEN_SORTEDMULTI,
    TOKEN_TR,
    // TOKEN_ADDR,     // unsupported
    // TOKEN_RAW,      // unsupported
} PolicyNodeType;

// TODO: the following structures are using size_t for all integers to avoid alignment problems;
//       if memory is an issue, we could use a packed version instead, but care needs to be taken
//       when accessing pointers, since they would be unaligned.

// abstract type for all nodes
typedef struct {
    PolicyNodeType type;
    void *node_data;  // subtypes will redefine this
} policy_node_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_SH, == TOKEN_WSH
    policy_node_t *script;
} policy_node_with_script_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_PK, == TOKEN_PKH, == TOKEN_WPKH
    size_t key_index;     // index of the key
} policy_node_with_key_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_MULTI, == TOKEN_SORTEDMULTI
    size_t k;             // threshold
    size_t n;             // number of keys
    size_t *key_indexes;  // pointer to array of exactly n key indexes
} policy_node_multisig_t;

typedef enum {
    SCRIPT_TYPE_P2PKH = 0x00,
    SCRIPT_TYPE_P2SH = 0x01,
    SCRIPT_TYPE_P2WPKH = 0x02,
    SCRIPT_TYPE_P2WSH = 0x03,
    SCRIPT_TYPE_P2TR = 0x04
} script_type_e;

/**
 * TODO: docs
 */
int read_policy_map_wallet(buffer_t *buffer, policy_map_wallet_header_t *header);

/**
 *
 * Parses a string representing the key information for a policy map wallet (multisig).
 * The string is compatible with the output descriptor format, except that the pubkey must _not_
 * have derivation steps (the key origin info, if present, does have derivation steps from the
 * master key fingerprint). The serialized base58check-encoded pubkey is _not_ validated.
 *
 * For example:
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out);

/**
 * TODO: docs
 */
int parse_policy_map(buffer_t *in_buf, void *out, size_t out_len);

int get_script_type(const uint8_t script[], size_t script_len);

#ifndef SKIP_FOR_CMOCKA

int get_script_address(const uint8_t script[],
                       size_t script_len,
                       global_context_t *coin_config,
                       char *out,
                       size_t out_len);

// /**
//  * TODO: docs
//  */
// void hash_update_append_wallet_header(cx_hash_t *hash_context, multisig_wallet_header_t *header);

// /**
//  * Parses a policy map for the supported wallet types, filling the 'out' buffer.
//  * Fails if any parsing error occurs, or if the buffer is not exhausted exactly.
//  * Returns -1 on failure
//  */
// int buffer_read_multisig_policy_map(buffer_t *buffer, multisig_wallet_policy_t *out);

/**
 * TODO: docs
 */
void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);

#endif
