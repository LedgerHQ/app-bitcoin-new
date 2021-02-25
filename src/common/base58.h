#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

/**
 * Maximum length of input when decoding in base 58.
 */
#define MAX_DEC_INPUT_SIZE 164
/**
 * Maximum length of input when encoding in base 58.
 */
#define MAX_ENC_INPUT_SIZE 120

/**
 * Decode input string in base 58.
 *
 * @see https://tools.ietf.org/html/draft-msporny-base58-02
 *
 * @param[in]  in
 *   Pointer to input string buffer.
 * @param[in]  in_len
 *   Length of the input string buffer.
 * @param[out] out
 *   Pointer to output byte buffer.
 * @param[in]  out_len
 *   Maximum length to write in output byte buffer.
 *
 * @return number of bytes decoded, -1 otherwise.
 *
 */
int base58_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len);

/**
 * Encode input bytes in base 58.
 *
 * @see https://tools.ietf.org/html/draft-msporny-base58-02
 *
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of the input byte buffer.
 * @param[out] out
 *   Pointer to output string buffer.
 * @param[in]  out_len
 *   Maximum length to write in output byte buffer.
 *
 * @return number of bytes encoded, -1 otherwise.
 *
 */
int base58_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len);
