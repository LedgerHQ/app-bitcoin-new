#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

/**
 * Structure for global context.
 */
typedef struct {
    uint32_t bip32_pubkey_version;    // version bytes for bip32 pubkeys
    const uint32_t *bip44_coin_types; // pointer to array of supported coin types
    const char *native_segwit_prefix; // human-readable part of segwit addresses
    uint16_t p2pkh_version;           // version for P2PKH addresses
    uint16_t p2sh_version;            // version for P2SH addresses
    uint8_t bip44_coin_types_len;     // length of the bip44_coin_types array
} global_context_t;
