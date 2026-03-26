#pragma once

#include <stdint.h>
#include <string.h>

/* SDK headers */
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
 * Get the total number of remaining readable bytes from the concatenation of two buffers.
 *
 * @param[in] buffers Array of two pointers to buffers.
 *
 * @return the sum of remaining bytes in both buffers.
 */
size_t dbuffer_get_length(buffer_t *buffers[2]);

/**
 * Check whether at least n bytes can be read from the concatenation of two buffers.
 *
 * @param[in] buffers Array of two pointers to buffers.
 * @param[in] n       Number of bytes to check for.
 *
 * @return true if at least n bytes remain across both buffers, false otherwise.
 */
bool dbuffer_can_read(buffer_t *buffers[2], size_t n);

/**
 * Read n bytes from the concatenation of two buffers into out.
 * Bytes are consumed from the first buffer before the second.
 *
 * @param[in]  buffers Array of two pointers to buffers.
 * @param[out] out     Destination buffer; must be at least n bytes long.
 * @param[in]  n       Number of bytes to read.
 *
 * @return true on success, false if fewer than n bytes are available.
 */
bool dbuffer_read_bytes(buffer_t *buffers[2], uint8_t *out, size_t n);

/**
 * Read a single byte from the concatenation of two buffers.
 *
 * @param[in]  buffers Array of two pointers to buffers.
 * @param[out] out     Pointer to store the read byte.
 *
 * @return true on success, false if no bytes are available.
 */
bool dbuffer_read_u8(buffer_t *buffers[2], uint8_t *out);

/**
 * Read a 16-bit unsigned integer from the concatenation of two buffers.
 *
 * @param[in]  buffers    Array of two pointers to buffers.
 * @param[out] out        Pointer to store the read value.
 * @param[in]  endianness Byte order (BE or LE).
 *
 * @return true on success, false if fewer than 2 bytes are available.
 */
bool dbuffer_read_u16(buffer_t *buffers[2], uint16_t *out, endianness_t endianness);

/**
 * Read a 32-bit unsigned integer from the concatenation of two buffers.
 *
 * @param[in]  buffers    Array of two pointers to buffers.
 * @param[out] out        Pointer to store the read value.
 * @param[in]  endianness Byte order (BE or LE).
 *
 * @return true on success, false if fewer than 4 bytes are available.
 */
bool dbuffer_read_u32(buffer_t *buffers[2], uint32_t *out, endianness_t endianness);

/**
 * Read a Bitcoin-style variable-length integer from the concatenation of two buffers.
 * The encoding uses 1, 3, 5, or 9 bytes depending on the value prefix.
 *
 * @param[in]  buffers Array of two pointers to buffers.
 * @param[out] out     Pointer to store the decoded value.
 *
 * @return true on success, false if there are not enough bytes available.
 */
bool dbuffer_read_varint(buffer_t *buffers[2], uint64_t *out);

/**
 * Initialize a parser context, resetting the step counter and setting the state pointer.
 *
 * @param[out] parser_context Parser context to initialize.
 * @param[in]  state          Pointer to the parser-specific state structure.
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
 * Execute a sequence of parsing steps, resuming from the current step in the parser context.
 * Each step is called with the parser state and the pair of buffers. Execution advances to the
 * next step when a step returns 1, and stops when a step returns 0 (needs more data) or -1
 * (error).
 *
 * @param[in]     parsing_steps  Array of parsing step function pointers.
 * @param[in]     n_steps        Number of steps in the array.
 * @param[in,out] parser_context Parser context tracking the current step and state.
 * @param[in]     buffers        Array of two pointers to buffers containing the data to parse.
 * @param[in]     pic_fn         PIC address-translation function, or NULL if not needed.
 *
 * @return 1 if all steps completed, 0 if more data is needed, -1 on parsing error.
 */
int parser_run(const parsing_step_t *parsing_steps,
               size_t n_steps,
               parser_context_t *parser_context,
               buffer_t *buffers[2],
               void *(*pic_fn)(void *) );
