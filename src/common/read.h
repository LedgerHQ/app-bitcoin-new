#pragma once

#include <stdint.h>  // uint*_t
#include <stddef.h>  // size_t

/**
 * Read 2 bytes as Big Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 2 bytes value read from buffer.
 *
 */
uint16_t read_u16_be(const uint8_t *ptr, size_t offset);

/**
 * Read 4 bytes as Big Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 4 bytes value read from buffer.
 *
 */
uint32_t read_u32_be(const uint8_t *ptr, size_t offset);

/**
 * Read 8 bytes as Big Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 8 bytes value read from buffer.
 *
 */
uint64_t read_u64_be(const uint8_t *ptr, size_t offset);

/**
 * Read 2 bytes as Little Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 2 bytes value read from buffer.
 *
 */
uint16_t read_u16_le(const uint8_t *ptr, size_t offset);

/**
 * Read 4 bytes as Little Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 4 bytes value read from buffer.
 *
 */
uint32_t read_u32_le(const uint8_t *ptr, size_t offset);

/**
 * Read 8 bytes as Little Endian from byte buffer.
 *
 * @param[in] ptr
 *   Pointer to byte buffer.
 * @param[in] offset
 *   Offset in the byte buffer.
 *
 * @return 8 bytes value read from buffer.
 *
 */
uint64_t read_u64_le(const uint8_t *ptr, size_t offset);
