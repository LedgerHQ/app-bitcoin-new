#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* SDK headers */
#include "buffer.h"

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
