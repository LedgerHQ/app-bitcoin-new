#pragma once

#include <stdint.h>
#include <assert.h>

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

#define MAX_POLICY_MAP_STR_LENGTH 110  // TODO: increase limit, at least on non-NanoS

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
    (1 + 1 + MAX_POLICY_MAP_NAME_LENGTH + 1 + MAX_POLICY_MAP_STR_LENGTH + 1 + 32)

// Maximum size of a parsed policy map in memory
#define MAX_POLICY_MAP_BYTES 256  // TODO: this is too large on Nano S

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
    TOKEN_PK,
    TOKEN_PKH,
    TOKEN_WPKH,
    // TOKEN_COMBO     // disabled, does not mix well with the script policy language
    TOKEN_MULTI,
    TOKEN_SORTEDMULTI,
    TOKEN_TR,
    // TOKEN_ADDR,     // unsupported
    // TOKEN_RAW,      // unsupported

    /* miniscript tokens */

    TOKEN_0,
    TOKEN_1,
    TOKEN_PK_K,
    TOKEN_PK_H,
    TOKEN_OLDER,
    TOKEN_AFTER,
    TOKEN_SHA256,
    TOKEN_HASH256,
    TOKEN_RIPEMD160,
    TOKEN_HASH160,
    TOKEN_ANDOR,
    TOKEN_AND_V,
    TOKEN_AND_B,
    TOKEN_AND_N,
    TOKEN_OR_B,
    TOKEN_OR_C,
    TOKEN_OR_D,
    TOKEN_OR_I,
    TOKEN_THRESH,
    // wrappers
    TOKEN_A,
    TOKEN_S,
    TOKEN_C,
    TOKEN_T,
    TOKEN_D,
    TOKEN_V,
    TOKEN_J,
    TOKEN_N,
    TOKEN_L,
    TOKEN_U,
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
    PolicyNodeType type;
} policy_node_constant_t;

typedef struct {
    PolicyNodeType type;
    policy_node_t *script;
} policy_node_with_script_t;

typedef struct {
    PolicyNodeType type;
    union {
        policy_node_t *scripts[1];
        policy_node_t *script;  // alias of scripts[0] for convenience
    };
} policy_node_with_script1_t;

typedef struct {
    PolicyNodeType type;
    policy_node_t *scripts[2];
} policy_node_with_script2_t;

typedef struct {
    PolicyNodeType type;
    policy_node_t *scripts[3];
} policy_node_with_script3_t;

// generic type with pointer for up to 3 (but constant) number of child scripts
typedef policy_node_with_script3_t policy_node_with_scripts_t;

typedef struct {
    PolicyNodeType type;
    size_t key_index;  // index of the key
} policy_node_with_key_t;

typedef struct {
    PolicyNodeType type;
    uint32_t n;
} policy_node_with_uint32_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_MULTI, == TOKEN_SORTEDMULTI
    size_t k;             // threshold
    size_t n;             // number of keys
    size_t *key_indexes;  // pointer to array of exactly n key indexes
} policy_node_multisig_t;

typedef struct policy_node_scriptlist_s {
    policy_node_t *script;
    struct policy_node_scriptlist_s *next;
} policy_node_scriptlist_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_THRESH
    size_t k;             // threshold
    size_t n;             // number of child script (TODO: remove?)
    policy_node_scriptlist_t
        *scriptlist;  // pointer to array of exactly n pointers to child scripts
} policy_node_thresh_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_SHA160, TOKEN_HASH160
    uint8_t h[20];
} policy_node_with_hash_160_t;

typedef struct {
    PolicyNodeType type;  // == TOKEN_SHA256, TOKEN_HASH256
    uint8_t h[32];
} policy_node_with_hash_256_t;

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

#ifndef SKIP_FOR_CMOCKA

/**
 * TODO: docs
 */
void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);

#endif
