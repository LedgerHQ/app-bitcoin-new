#pragma once

#include <stdint.h>
#include <string.h>
#include "buffer.h"

typedef struct {
    size_t cur_step;
    void *state;  // subtyped for each specific parser
} parser_context_t;

/**
 * A parsing step gets a pointer to the parser's state, and an array of two pointers to buffers. The
 * concatenation o the two buffer is the (possibly incomplete) data to be parsed. The parsing step
 * returns -1 in case of parsing error (e.g.: invalid value was parsed); 1 if the parsing step is
 * completed successfully, 0 if more data is expected.
 * Any remaining data in the concatenation of the two buffers' remaining content must be passed in
 * the next call to the parser, that will continue from the same parsing step.
 */
typedef int (*parsing_step_t)(void *, buffer_t *[2]);

// Convenience functions to handle reading from the concatenation of two buffers.
// All these functions are analogous to the corresponding buffer_read_X functions, but they exhaust
// the first buffer before reading from the second buffer.

/**
 * Get the total remaining length readable from this pair of buffers.
 * TODO: finish docs
 */
size_t dbuffer_get_length(buffer_t *buffers[2]);

/**
 * TODO: docs.
 */
bool dbuffer_can_read(buffer_t *buffers[2], size_t n);

/**
 * TODO: docs.
 */
bool dbuffer_read_bytes(buffer_t *buffers[2], uint8_t *out, size_t n);

/**
 * TODO: docs.
 */
bool dbuffer_read_u8(buffer_t *buffers[2], uint8_t *out);

/**
 * TODO: docs.
 */
bool dbuffer_read_u16(buffer_t *buffers[2], uint16_t *out, endianness_t endianness);

/**
 * TODO: docs.
 */
bool dbuffer_read_u32(buffer_t *buffers[2], uint32_t *out, endianness_t endianness);

/**
 * TODO: docs.
 */
bool dbuffer_read_varint(buffer_t *buffers[2], uint64_t *out);

/**
 * TODO: docs.
 */
static inline void parser_init_context(parser_context_t *parser_context, void *state) {
    parser_context->cur_step = 0;
    parser_context->state = state;
}

/**
 * Moves the concatenation of all the remaining bytes in the two buffers into the memory pointed by
 * the first buffer, as long as the number of remaining bytes is at most max_byte. The offset of the
 * first buffer is set to 0, and the new size reflects the total size
 *
 * Returns true on success; false if the total number of remaining bytes is larger than max_size.
 */
bool parser_consolidate_buffers(buffer_t *buffers[2], size_t max_size);

/**
 * TODO: docs
 */
int parser_run(const parsing_step_t *parsing_steps,
               size_t n_steps,
               parser_context_t *parser_context,
               buffer_t *buffers[2],
               void *(*pic_fn)(void *) );
