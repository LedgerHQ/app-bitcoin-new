#pragma once

#include <stddef.h>   // size_t
#include <stdint.h>   // int*_t, uint*_t
#include <stdbool.h>  // bool

/**
 * Format 64-bit signed integer as string.
 *
 * @param[out] dst
 *   Pointer to output string.
 * @param[in]  dst_len
 *   Length of output string.
 * @param[in]  value
 *   64-bit signed integer to format.
 *
 * @return true if success, false otherwise.
 *
 */
bool format_i64(char *dst, size_t dst_len, const int64_t value);

/**
 * Format 64-bit unsigned integer as string.
 *
 * @param[out] dst
 *   Pointer to output string.
 * @param[in]  dst_len
 *   Length of output string.
 * @param[in]  value
 *   64-bit unsigned integer to format.
 *
 * @return true if success, false otherwise.
 *
 */
bool format_u64(char *dst, size_t dst_len, uint64_t value);

/**
 * Format 64-bit unsigned integer as string with decimals.
 *
 * @param[out] dst
 *   Pointer to output string.
 * @param[in]  dst_len
 *   Length of output string.
 * @param[in]  value
 *   64-bit unsigned integer to format.
 * @param[in]  decimals
 *   Number of digits after decimal separator.
 *
 * @return true if success, false otherwise.
 *
 */
bool format_fpu64(char *dst, size_t dst_len, const uint64_t value, uint8_t decimals);

/**
 * Format byte buffer to uppercase hexadecimal string.
 *
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of input byte buffer.
 * @param[out] out
 *   Pointer to output string.
 * @param[in]  out_len
 *   Length of output string.
 *
 * @return number of bytes written if success, -1 otherwise.
 *
 */
int format_hex(const uint8_t *in, size_t in_len, char *out, size_t out_len);
