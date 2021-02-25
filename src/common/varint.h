#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

/**
 * Size of value represented as Bitcoin-like varint.
 *
 * @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 *
 * @param[in] value
 *   64-bit unsigned integer to compute varint size.
 *
 * @return number of bytes to write value as varint (1, 3, 5 or 9 bytes).
 *
 */
uint8_t varint_size(uint64_t value);

/**
 * Read Bitcoin-like varint from byte buffer.
 *
 * @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 *
 * @param[in]  in
 *   Pointer to input byte buffer.
 * @param[in]  in_len
 *   Length of the input byte buffer.
 * @param[out] value
 *   Pointer to 64-bit unsigned integer to output varint.
 *
 * @return number of bytes read (1, 3, 5 or 9 bytes), -1 otherwise.
 *
 */
int varint_read(const uint8_t *in, size_t in_len, uint64_t *value);

/**
 * Write Bitcoin-like varint to byte buffer.
 *
 * @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 *
 * @param[out] out
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   64-bit unsigned integer to write as varint.
 *
 * @return number of bytes written (1, 3, 5 or 9 bytes), -1 otherwise.
 *
 */
int varint_write(uint8_t *out, size_t offset, uint64_t value);
