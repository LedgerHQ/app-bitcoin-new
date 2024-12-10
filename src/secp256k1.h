#pragma once

#include <stdint.h>

/**
 * Generator for secp256k1, value 'g' defined in "Standards for Efficient Cryptography"
 * (SEC2) 2.7.1.
 */
extern const uint8_t secp256k1_generator[65];

/**
 * Modulo for secp256k1
 */
extern const uint8_t secp256k1_p[32];

/**
 * Curve order for secp256k1
 */
extern const uint8_t secp256k1_n[32];

/**
 * (p + 1)/4, used to calculate square roots in secp256k1
 */
extern const uint8_t secp256k1_sqr_exponent[32];
