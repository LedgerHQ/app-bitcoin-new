#pragma once

#include <stdint.h>

/**
 * Classification result for a sighash type.
 */
typedef enum {
    SIGHASH_CLASS_SAFE,        // SIGHASH_ALL or SIGHASH_DEFAULT (for segwit v1+)
    SIGHASH_CLASS_NON_SAFE,    // Non-standard but recognized (NONE, SINGLE, ANYONECANPAY|*)
    SIGHASH_CLASS_UNSUPPORTED  // Completely unsupported sighash type
} sighash_class_t;

/**
 * Classify a sighash type according to the security model:
 *
 * SAFE:
 *   - SIGHASH_DEFAULT (0x00) when segwit_version > 0 (Taproot)
 *   - SIGHASH_ALL (0x01)
 *
 * NON_SAFE (requires user opt-in via settings):
 *   - SIGHASH_NONE (0x02)
 *   - SIGHASH_SINGLE (0x03)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_ALL (0x81)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_NONE (0x82)
 *   - SIGHASH_ANYONECANPAY | SIGHASH_SINGLE (0x83)
 *
 * UNSUPPORTED: everything else
 *
 * @param sighash_type    The PSBT_IN_SIGHASH_TYPE value
 * @param segwit_version  The segwit version of the input (-1 for legacy)
 * @return                The classification of the sighash type
 */
static inline sighash_class_t classify_sighash(uint32_t sighash_type, int segwit_version) {
    // SIGHASH_DEFAULT is only valid for Taproot (segwit v1+)
    if (((segwit_version > 0) && (sighash_type == 0x00000000 /* SIGHASH_DEFAULT */)) ||
        (sighash_type == 0x00000001 /* SIGHASH_ALL */)) {
        return SIGHASH_CLASS_SAFE;
    }

    if ((segwit_version >= 0) &&
        ((sighash_type == 0x00000002 /* SIGHASH_NONE */) ||
         (sighash_type == 0x00000003 /* SIGHASH_SINGLE */) ||
         (sighash_type == (0x00000080 | 0x00000001) /* SIGHASH_ANYONECANPAY | SIGHASH_ALL */) ||
         (sighash_type == (0x00000080 | 0x00000002) /* SIGHASH_ANYONECANPAY | SIGHASH_NONE */) ||
         (sighash_type == (0x00000080 | 0x00000003) /* SIGHASH_ANYONECANPAY | SIGHASH_SINGLE */))) {
        return SIGHASH_CLASS_NON_SAFE;
    }

    return SIGHASH_CLASS_UNSUPPORTED;
}
