
#pragma once

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"

/**
 * Derive private key given BIP32 path.
 *
 * @param[out] private_key
 *   Pointer to private key.
 * @param[out] chain_code
 *   Pointer to 32 bytes array for chain code.
 * @param[in]  bip32_path
 *   Pointer to buffer with BIP32 path.
 * @param[in]  bip32_path_len
 *   Number of path in BIP32 path.
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
int crypto_derive_private_key(cx_ecfp_private_key_t *private_key,
                              uint8_t chain_code[static 32],
                              const uint32_t *bip32_path,
                              uint8_t bip32_path_len);

/**
 * Initialize public key given private key.
 *
 * @param[in]  private_key
 *   Pointer to private key.
 * @param[out] public_key
 *   Pointer to public key.
 * @param[out] raw_public_key
 *   Pointer to raw public key.
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
int crypto_init_public_key(cx_ecfp_private_key_t *private_key,
                           cx_ecfp_public_key_t *public_key,
                           uint8_t raw_public_key[static 64]);


/**
 * Computes RIPEMD160(SHA256(in).
 *
 * @param[in] in
 *   Pointer to input data.
 * @param[in] in_len
 *   Length of input data.
 * @param[out] out
 *   Pointer to the 160-bit (20 bytes) output array.
 */
void crypto_hash160(uint8_t *in, uint16_t in_len, uint8_t *out);



/**
 * Computes the 33-bytes compressed public key from the uncompressed 65-bytes extended public key.
 *
 * @param[in] uncompressed_key
 *   Pointer to the uncompressed public key. The first byte must be 0x04, followed by 64 bytes public key data. 
 * @param[out] out
 *   Pointer to the output array, that must be 33 bytes long. The first byte of the output will be 0x02 or 0x03.
 *   It is allowed to set out == uncompressed_key, and in that case the computation will be in place.
 *   Otherwise, the input and output arrays MUST be non-overlapping.
 */
int crypto_get_compressed_pubkey(uint8_t uncompressed_key[static 65], uint8_t out[static 33]);

/**
 * Computes the checksum as the first 4 bytes of the double sha256 hash of the input data.
 * 
 * @param[in] in
 *   Pointer to the input data. 
 * @param[in] in_len
 *   Length of the input data. 
 * @param[out] out
 *   Pointer to the output buffer, which must contain at least 4 bytes.
 *   
 */
void crypto_get_checksum(const uint8_t *in, uint16_t in_len, uint8_t out[static 4]);

/**
 * Sign message hash in global context.
 *
 * @see G_context.bip32_path, G_context.tx_info.m_hash,
 * G_context.tx_info.signature.
 *
 * @return 0 if success, -1 otherwise.
 *
 * @throw INVALID_PARAMETER
 *
 */
// int crypto_sign_message(void);
