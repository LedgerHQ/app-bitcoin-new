#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

/**
 * Enumeration for endianness.
 */
typedef enum {
    BE,  /// Big Endian
    LE   /// Little Endian
} endianness_t;

typedef size_t buffer_snapshot_t;

/**
 * Struct for buffer with size and offset.
 */
typedef struct {
    uint8_t *ptr;   /// Pointer to byte buffer
    size_t size;    /// Size of byte buffer
    size_t offset;  /// Offset in byte buffer
} buffer_t;

/**
 * Tell whether buffer can read bytes or not.
 *
 * @param[in] buffer
 *   Pointer to input buffer struct.
 * @param[in] n
 *   Number of bytes to read in buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_can_read(const buffer_t *buffer, size_t n);

/**
 * Seek the buffer to specific offset.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Specific offset to seek.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_set(buffer_t *buffer, size_t offset);

/**
 * Seek buffer relatively to current offset.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Offset to seek relatively to `buffer->offset`.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_cur(buffer_t *buffer, size_t offset);

/**
 * Seek the buffer relatively to the end.
 *
 * @param[in,out] buffer
 *   Pointer to input buffer struct.
 * @param[in]     offset
 *   Offset to seek relatively to `buffer->size`.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_seek_end(buffer_t *buffer, size_t offset);

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
 * Read 2 bytes from buffer into uint16_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 16-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u16(buffer_t *buffer, uint16_t *value, endianness_t endianness);

/**
 * Read 4 bytes from buffer into uint32_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 32-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u32(buffer_t *buffer, uint32_t *value, endianness_t endianness);

/**
 * Read 8 bytes from buffer into uint64_t.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 64-bit unsigned integer read from buffer.
 * @param[in]      endianness
 *   Either BE (Big Endian) or LE (Little Endian).
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_u64(buffer_t *buffer, uint64_t *value, endianness_t endianness);

/**
 * Read Bitcoin-like varint from buffer into uint64_t.
 *
 * @see https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     value
 *   Pointer to 64-bit unsigned integer read from buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_varint(buffer_t *buffer, uint64_t *value);

/**
 * Read BIP32 path from buffer.
 *
 * @param[in,out]  buffer
 *   Pointer to input buffer struct.
 * @param[out]     out
 *   Pointer to output 32-bit integer buffer.
 * @param[in]      out_len
 *   Number of BIP32 paths read in the output buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool buffer_read_bip32_path(buffer_t *buffer, uint32_t *out, size_t out_len);

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
 * @param[in]  ptr
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
 * the buffer, or NULL otherwise. On success, the buffer is advanced by `size` bytes. If aligned ==
 * true, the returned pointer is 32-bit aligned (adding up to three padding bytes if necessary).
 */
void *buffer_alloc(buffer_t *buffer, size_t size, bool aligned);

/**
 * TODO: docs
 */
static inline buffer_snapshot_t buffer_snapshot(buffer_t *buffer) {
    return buffer->offset;
}

/**
 * TODO: docs
 */
static inline void buffer_restore(buffer_t *buffer, buffer_snapshot_t snapshot) {
    buffer->offset = snapshot;
}
