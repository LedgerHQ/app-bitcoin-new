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

#define WALLET_POLICY_VERSION_V1 1  // the legacy version of the first release
#define WALLET_POLICY_VERSION_V2 2  // the current full version

/**
 * Maximum supported number of keys for a wallet policy.
 */
#define MAX_WALLET_POLICY_COSIGNERS 5

/**
 * Maximum supported number of keys for a wallet policy.
 */
#define MAX_WALLET_POLICY_KEYS 5

// The string describing a pubkey can contain:
// - (optional) the key origin info, which we limit to 46 bytes (2 + 8 + 3*12 = 46 bytes)
// - the xpub itself (up to 113 characters)
// - optional, the "/**" suffix.
// Therefore, the total length of the key info string is at most 162 bytes.
#define MAX_POLICY_KEY_INFO_LEN_V1 (46 + MAX_SERIALIZED_PUBKEY_LENGTH + 3)

// In V1, there is no "/**" suffix, as that is no longer part of the key
#define MAX_POLICY_KEY_INFO_LEN_V2 (46 + MAX_SERIALIZED_PUBKEY_LENGTH)

#define MAX_POLICY_KEY_INFO_LEN MAX(MAX_POLICY_KEY_INFO_LEN_V1, MAX_POLICY_KEY_INFO_LEN_V2)

// longest supported policy in V1 is "sh(wsh(sortedmulti(5,@0,@1,@2,@3,@4)))", 38 bytes
#define MAX_WALLET_POLICY_STR_LENGTH_V1 40

#define MAX_WALLET_POLICY_STR_LENGTH_V2 128  // TODO: increase limit, at least on non-NanoS

#define MAX_WALLET_POLICY_STR_LENGTH \
    MAX(MAX_WALLET_POLICY_STR_LENGTH_V1, MAX_WALLET_POLICY_STR_LENGTH_V2)

#define MAX_WALLET_POLICY_NAME_LENGTH 16

// at most 92 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_POLICY_NAME_LENGTH bytes)
// policy length (1 byte)
// policy (max MAX_WALLET_POLICY_STR_LENGTH bytes)
// n_keys (1 byte)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1 \
    (1 + 1 + MAX_WALLET_POLICY_NAME_LENGTH + 1 + MAX_WALLET_POLICY_STR_LENGTH_V1 + 1 + 32)

// at most 100 bytes
// wallet type (1 byte)
// name length (1 byte)
// name (max MAX_WALLET_POLICY_NAME_LENGTH bytes)
// policy length (varint, up to 9 bytes)
// policy hash 32
// n_keys (varint, up to 9 bytes)
// keys_merkle_root (32 bytes)
#define MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2 \
    (1 + 1 + MAX_WALLET_POLICY_NAME_LENGTH + 9 + 32 + 9 + 32)

#define MAX_WALLET_POLICY_SERIALIZED_LENGTH \
    MAX(MAX_WALLET_POLICY_SERIALIZED_LENGTH_V1, MAX_WALLET_POLICY_SERIALIZED_LENGTH_V2)

// Maximum size of a parsed wallet descriptor template in memory
#define MAX_WALLET_POLICY_BYTES 256  // TODO: this is too large on Nano S

typedef struct {
    uint32_t master_key_derivation[MAX_BIP32_PATH_STEPS];
    uint8_t master_key_fingerprint[4];
    uint8_t master_key_derivation_len;
    uint8_t has_key_origin;
    uint8_t has_wildcard;  // true iff the keys ends with the wildcard (/ followed by **)
    char ext_pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} policy_map_key_info_t;

typedef struct {
    uint8_t version;  // supported values: WALLET_POLICY_VERSION_V1 and WALLET_POLICY_VERSION_V2
    uint8_t name_len;
    uint16_t policy_map_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];
    union {
        // TODO: rename to "descriptor_template"?
        char policy_map[MAX_WALLET_POLICY_STR_LENGTH_V1];  // used in V1
        uint8_t policy_map_sha256[32];                     // used in V2
    };
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

    TOKEN_INVALID = -1  // used to mark invalid tokens
} PolicyNodeType;

// miniscript basic types
#define MINISCRIPT_TYPE_B 0
#define MINISCRIPT_TYPE_V 1
#define MINISCRIPT_TYPE_K 2
#define MINISCRIPT_TYPE_W 3

typedef struct policy_node_s {
    PolicyNodeType type;
    struct {
        unsigned int is_miniscript : 1;
        unsigned int miniscript_type : 2;  // B, C, K or W
        unsigned int miniscript_mod_z : 1;
        unsigned int miniscript_mod_o : 1;
        unsigned int miniscript_mod_n : 1;
        unsigned int miniscript_mod_d : 1;
        unsigned int miniscript_mod_u : 1;
    } flags;  // 1 byte
} policy_node_t;

typedef struct {
    struct policy_node_s base;
} policy_node_constant_t;

typedef struct {
    struct policy_node_s base;
    policy_node_t *script;
} policy_node_with_script_t;

typedef struct {
    struct policy_node_s base;
    policy_node_t *scripts[2];
} policy_node_with_script2_t;

typedef struct {
    struct policy_node_s base;
    policy_node_t *scripts[3];
} policy_node_with_script3_t;

// generic type with pointer for up to 3 (but constant) number of child scripts
typedef policy_node_with_script3_t policy_node_with_scripts_t;

typedef struct {
    struct policy_node_s base;
    int16_t key_index;  // index of the key
} policy_node_with_key_t;

typedef struct {
    struct policy_node_s base;
    uint32_t n;
} policy_node_with_uint32_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_MULTI or TOKEN_SORTEDMULTI
    int16_t k;                  // threshold
    int16_t n;                  // number of keys
    int16_t *key_indexes;       // pointer to array of exactly n key indexes
} policy_node_multisig_t;

typedef struct policy_node_scriptlist_s {
    policy_node_t *script;
    struct policy_node_scriptlist_s *next;
} policy_node_scriptlist_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_THRESH
    int16_t k;                  // threshold
    int16_t n;                  // number of child scripts
    policy_node_scriptlist_t
        *scriptlist;  // pointer to array of exactly n pointers to child scripts
} policy_node_thresh_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA160 or TOKEN_HASH160
    uint8_t h[20];
} policy_node_with_hash_160_t;

typedef struct {
    struct policy_node_s base;  // type is TOKEN_SHA256 or TOKEN_HASH256
    uint8_t h[32];
} policy_node_with_hash_256_t;

/**
 * Parses the string in the `buffer` as a serialized policy map into `header`
 *
 * @param buffer the pointer to the buffer_t to parse
 * @param header the pointer to a `policy_map_wallet_header_t` structure
 * @return a negative number on failure, 0 on success.
 */
int read_wallet_policy_header(buffer_t *buffer, policy_map_wallet_header_t *header);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
// The compiler doesn't like /** inside a block comment, so we disable this warning temporarily.

/**
 * Parses a string representing the key information for a policy map wallet.
 * The string is compatible with the output descriptor format, except that the pubkey must _not_
 * have derivation steps (the key origin info, if present, does have derivation steps from the
 * master key fingerprint). The serialized base58check-encoded pubkey is _not_ validated.
 *
 * For WALLET_POLICY_VERSION_V1, the final suffix /** must be present and is part of the key
 * information. For WALLET_POLICY_VERSION_V2, parsing stops at the xpub.
 *
 * Example (V1):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/**"
 * Example (V2):
 * "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
 */
int parse_policy_map_key_info(buffer_t *buffer, policy_map_key_info_t *out, int version);

#pragma GCC diagnostic pop

/**
 * Parses `in_buf` as a policy map, constructing the abstract syntax tree in the buffer `out` of
 * size `out_len`.
 *
 * @param in_buf the buffer containing the policy map to parse
 * @param out the pointer to the output buffer, which must be 4-byte aligned
 * @param out_len the length of the output buffer
 * @param version either WALLET_POLICY_VERSION_V1 or WALLET_POLICY_VERSION_V2
 * @return 0 on success; -1 in case of parsing error, if the output buffer is unaligned, or if the
 * output buffer is too small.
 */
int parse_policy_map(buffer_t *in_buf, void *out, size_t out_len, int version);

#ifndef SKIP_FOR_CMOCKA

/**
 * Computes the id of the policy map wallet (commitment to header + policy map + keys_info), as per
 * specifications.
 *
 * @param wallet_header
 * @param out a pointer to a 32-byte array for the output
 */
void get_policy_wallet_id(policy_map_wallet_header_t *wallet_header, uint8_t out[static 32]);

#endif
