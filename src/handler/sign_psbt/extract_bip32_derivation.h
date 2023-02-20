#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/bip32.h"

/**
 * Convenience function to extract the BIP32 derivation part from a PSBT field key type
 * PSBT_{IN,OUT}_BIP32_DERIVATION or PSBT_{IN,OUT}_TAP_BIP32_DERIVATION.
 * This is needed because the tapscript versions can be very large, so it needs to
 * be parsed while streaming it.
 */
int extract_bip32_derivation(dispatcher_context_t *dc,
                             int psbt_key_type,
                             const uint8_t values_root[static 32],
                             uint32_t merkle_tree_size,
                             int index,
                             uint32_t out[static 1 + MAX_BIP32_PATH_STEPS]);