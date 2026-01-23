#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* SDK headers */
#include "buffer.h"

typedef size_t buffer_snapshot_t;

/**
 * Returns the pointer to byte in the current position of the buffer.
 *
 * @param[in] buffer
 *   Pointer to input buffer struct.
 *
 * @return the pointer to the current position.
 *
 */
static inline uint8_t *buffer_get_cur(const buffer_t *buffer) {
    return (uint8_t *) (buffer->ptr + buffer->offset);
}

/**
 * Read 1 byte from buffer into uint8_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 8-bit unsigned integer read from buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u8(buffer_t *buffer, uint8_t *value);

/**
 * Read 1 byte from buffer into uint8_t without advancing the current position in the buffer.
 * Returns `true` on success, `false` if the buffer was empty; `value` is not changed in case of
 * failure.
 *
 * @param[in]  buffer
 *   Pointer to input buffer struct.
 * @param[out]  value
 *   Pointer to 8-bit unsigned integer read from buffer.
 *
 * @return true if success, false otherwise.
 */
bool buffer_peek(const buffer_t *buffer, uint8_t *value);

/**
 * Read 1 byte at position `n` from buffer into uint8_t without advancing the current position in
 * the buffer. Returns `true` on success, `false` if the buffer is not large enough; `value` is not
 * changed in case of failure.
 *
 * @param[in]  buffer
 *   Pointer to input buffer struct.
 * @param[out]  n
 *   Index of the byte to read, where the immediate next byte has index 0.
 * @param[out]  value
 *   Pointer to 8-bit unsigned integer read from buffer.
 *
 * @return true if success, false otherwise.
 */
bool buffer_peek_n(const buffer_t *buffer, size_t n, uint8_t *value);

/**
 * Read n bytes from buffer, and stores them in out.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     out
 *   Pointer to output buffer. It is the responsibility of the caller to make sure that the output
 * buffer is at least n bytes long.
 * @param[in]      n
 *   Number of bytes to read from buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_bytes(buffer_t *buffer, uint8_t *out, size_t n);

/**
 * Write a uint8_t into a buffer.
 *
 * @param[in,out]  buffer
 *   Pointer to output buffer struct.
 * @param[out]     value
 *   Value to be written.
 *
 * @return true if success, false if not enough space left in the buffer.
 *
 */
bool buffer_write_u8(buffer_t *buffer, uint8_t value);

/**
 * Write a uint16_t into the buffer as 2 bytes, with the given endianness.
 *
 * @param[in,out]  buffer
 *   Pointer to output buffer struct.
 * @param[out]     value
 *   Value to be written.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false if not enough space left in the buffer.
 *
 */
bool buffer_write_u16(buffer_t *buffer, uint16_t value, endianness_t endianness);

/**
 * Write a uint32_t into the buffer as 4 bytes, with the given endianness.
 *
 * @param[in,out]  buffer
 *   Pointer to output buffer struct.
 * @param[out]     value
 *   Value to be written.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false if not enough space left in the buffer.
 *
 */
bool buffer_write_u32(buffer_t *buffer, uint32_t value, endianness_t endianness);

/**
 * Write a uint64_t into the buffer as 8 bytes, with the given endianness.
 *
 * @param[in,out]  buffer
 *   Pointer to output buffer struct.
 * @param[out]     value
 *   Value to be written.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false if not enough space left in the buffer.
 *
 */
bool buffer_write_u64(buffer_t *buffer, uint64_t value, endianness_t endianness);

/**
 * Write a number of bytes to a buffer.
 *
 * @param[in,out]  buffer
 *   Pointer to output buffer struct.
 * @param[in]      data
 *   Pointer to bytes to be written.
 * @param[in]      n
 *   Size of bytes to be written.
 *
 * @return true if success, false if not enough space left in the buffer.
 *
 */
bool buffer_write_bytes(buffer_t *buffer, const uint8_t *data, size_t n);

/**
 * Creates a buffer pointing at ptr and with the given size; the initial offset is 0.
 *
 * @param[in,out]  ptr
 *   Pointer to the buffer's data.
 * @param[in]  size
 *   Size of the buffer.
 *
 * @return the new buffer with the given pointer and size.
 *
 */
static inline buffer_t buffer_create(void *ptr, size_t size) {
    return (buffer_t){.ptr = ptr, .size = size, .offset = 0};
}

/**
 * Returns a pointer to the current position in the buffer if at least `size` bytes are available in
 * the buffer (possibly after skipping some bytes to guarantee alignment), or NULL otherwise. On
 * success, the buffer is advanced by `size` bytes. If `aligned == true`, the returned pointer is
 * 32-bit aligned (adding up to three padding bytes if necessary). The buffer is not advanced in
 * case of failure.
 *
 * @param[in,out]  buffer The buffer in which the memory is to be allocated.
 * @param[in]  size The number of bytes allocated within `buffer`.
 * @param[in]  aligned If `true`, makes sure that the returned pointer is 32-bit aligned.
 *
 * @return a pointer to the allocated memory within the buffer.
 */
void *buffer_alloc(buffer_t *buffer, size_t size, bool aligned);

/**
 * Checks if the current position in the buffer is aligned in memory to a 4-byte boundary.
 *
 * @param[in]  buffer Pointer to a buffer struct.
 *
 * @return `true` if the current position in the buffer is aligned, `false` otherwise.
 */
static inline bool buffer_is_cur_aligned(const buffer_t *buffer) {
    return (size_t) (buffer->ptr + buffer->offset) % 4 == 0;
}

/**
 * Saves a snapshot of the current position within the buffer.
 *
 * @param[in] buffer The buffer whose position is saved.
 *
 * @return a snapshot that can be restored with `buffer_restore`.
 */
static inline buffer_snapshot_t buffer_snapshot(const buffer_t *buffer) {
    return buffer->offset;
}

/**
 * Restores a previously taken snapshot of the buffer.
 *
 * @param[in,out] snapshot The snapshot previously returned by a call to `buffer_snapshot` on the
 * same buffer. The behavior is undefined if any other value is passed as `snapshot`.
 */
static inline void buffer_restore(buffer_t *buffer, buffer_snapshot_t snapshot) {
    buffer->offset = snapshot;
}
