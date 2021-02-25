#pragma once

#include <stdint.h>  // uint*_t
#include <stddef.h>  // size_t

/**
 * Write 16-bit unsigned integer value as Big Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   16-bit unsigned integer to write in output byte buffer as Big Endian.
 *
 */
void write_u16_be(const uint8_t *ptr, size_t offset, uint16_t value);

/**
 * Write 32-bit unsigned integer value as Big Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   32-bit unsigned integer to write in output byte buffer as Big Endian.
 *
 */
void write_u32_be(uint8_t *ptr, size_t offset, uint32_t value);

/**
 * Write 64-bit unsigned integer value as Big Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   64-bit unsigned integer to write in output byte buffer as Big Endian.
 *
 */
void write_u64_be(uint8_t *ptr, size_t offset, uint64_t value);

/**
 * Write 16-bit unsigned integer value as Little Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   16-bit unsigned integer to write in output byte buffer as Little Endian.
 *
 */
void write_u16_le(uint8_t *ptr, size_t offset, uint16_t value);

/**
 * Write 32-bit unsigned integer value as Little Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   32-bit unsigned integer to write in output byte buffer as Little Endian.
 *
 */
void write_u32_le(uint8_t *ptr, size_t offset, uint32_t value);

/**
 * Write 64-bit unsigned integer value as Little Endian.
 *
 * @param[out] ptr
 *   Pointer to output byte buffer.
 * @param[in]  offset
 *   Offset in the output byte buffer.
 * @param[in]  value
 *   64-bit unsigned integer to write in output byte buffer as Little Endian.
 *
 */
void write_u64_le(uint8_t *ptr, size_t offset, uint64_t value);
