#pragma once

#include <stdint.h>
#include <stddef.h>

// TODO: rename once BIP number is assigned
static uint8_t BIP_MUSIG_CHAINCODE[32] = {
    0x86, 0x80, 0x87, 0xCA, 0x02, 0xA6, 0xF9, 0x74, 0xC4, 0x59, 0x89, 0x24, 0xC3, 0x6B, 0x57, 0x76,
    0x2D, 0x32, 0xCB, 0x45, 0x71, 0x71, 0x67, 0xE3, 0x00, 0x62, 0x2C, 0x71, 0x67, 0xE3, 0x89, 0x65};

typedef uint8_t plain_pk_t[33];
typedef uint8_t xonly_pk_t[32];

// An uncompressed pubkey, encoded as 04||x||y, where x and y are 32-byte big-endian coordinates.
// If the first byte (prefix) is 0, encodes the point at infinity.
typedef struct {
    union {
        uint8_t raw[65];
        struct {
            uint8_t prefix;  // 0 for the point at infinity, otherwise 4.
            uint8_t x[32];
            uint8_t y[32];
        };
    };
} point_t;

typedef struct musig_keyagg_context_s {
    point_t Q;
    uint8_t gacc[32];
    uint8_t tacc[32];
} musig_keyagg_context_t;

/**
 * Computes the KeyAgg Context per BIP-0327.
 *
 * @param[in]  pubkeys
 *   Pointer to a list of pubkeys.
 * @param[in]  n_keys
 *   Number of pubkeys.
 * @param[out]  musig_keyagg_context_t
 *   Pointer to receive the musig KeyAgg Context.
 *
 * @return 0 on success, a negative number in case of error.
 */
int musig_key_agg(const plain_pk_t pubkeys[], size_t n_keys, musig_keyagg_context_t *ctx);
