#pragma once

#include <stdint.h>
#include <stdbool.h>

/**
 * Returns the size in bytes of a bitvector that can contain n bits.
 */
#define BITVECTOR_REAL_SIZE(n) ((n + 7) / 8)

/**
 * Returns the value in the `i`-th position of the vector of bits.
 * There is no bounds checking, hence the caller is responsible for avoiding overflows.
 *
 * @param vec pointer to the bitvector
 * @param i position in the bitvector
 * @return the element in the i-th position in the bitvector
 */
static inline bool bitvector_get(const uint8_t *vec, unsigned int i) {
    unsigned int byte_pos = i / 8;
    unsigned int shift = 7 - i % 8;
    return (vec[byte_pos] >> shift) & 1;
}

/**
 * Sets the `i`-th element of the vector of bits to `value`
 * There is no bounds checking, hence the caller is responsible for avoiding overflows.
 *
 * @param vec pointer to the bitvector
 * @param i position in the bitvector
 * @param value
 */
static inline void bitvector_set(uint8_t *vec, unsigned int i, bool value) {
    unsigned int byte_pos = i / 8;
    unsigned int shift = 7 - i % 8;
    uint8_t mask = (uint8_t) (1 << shift);

    if (value) {
        vec[byte_pos] |= mask;
    } else {
        vec[byte_pos] &= ~mask;
    }
}