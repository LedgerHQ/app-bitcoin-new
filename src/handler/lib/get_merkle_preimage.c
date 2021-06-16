#include "string.h"

#include "get_merkle_preimage.h"

#include "../../common/buffer.h"
#include "../../crypto.h"
#include "../client_commands.h"

// TODO: refactor common code with stream_preimage.c

int call_get_merkle_preimage(dispatcher_context_t *dispatcher_context,
                             const uint8_t hash[static 20],
                             uint8_t *out_ptr,
                             size_t out_ptr_len) {

    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    cx_ripemd160_t hash_context;

    cx_ripemd160_init(&hash_context);

    uint8_t get_preimage_req[1 + 20];
    get_preimage_req[0] = CCMD_GET_PREIMAGE;
    memcpy(&get_preimage_req[1], hash, 20);

    if (dispatcher_context->process_interruption(dispatcher_context, get_preimage_req, sizeof(get_preimage_req)) < 0) {
        return -1;
    }

    uint64_t preimage_len;

    uint8_t partial_data_len;

    if (!buffer_read_varint(&dispatcher_context->read_buffer, &preimage_len)
        || !buffer_read_u8(&dispatcher_context->read_buffer, &partial_data_len)
        || !buffer_can_read(&dispatcher_context->read_buffer, partial_data_len))
    {
        return -2;
    }

    if (preimage_len == 0 || partial_data_len == 0) {
        return -3;
    }

    if (preimage_len - 1 > out_ptr_len) {
        PRINTF("Output buffer too short\n");
        return -4;
    }

    if (partial_data_len > preimage_len) {
        return -5;
    }

    uint8_t *data_ptr = dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

    // update hash
    crypto_hash_update(&hash_context.header, data_ptr, partial_data_len);

    buffer_t out_buffer = buffer_create(out_ptr, out_ptr_len);

    // write bytes to output
    buffer_write_bytes(&out_buffer, data_ptr + 1, partial_data_len - 1);    // we skip the first byte

    size_t bytes_remaining = (size_t)preimage_len - partial_data_len;

    while (bytes_remaining > 0) {
        uint8_t get_more_elements_req[] = { CCMD_GET_MORE_ELEMENTS };
        if (dispatcher_context->process_interruption(dispatcher_context, get_more_elements_req, 1) < 0) {
            return -6;
        }

        // Parse response to CCMD_GET_MORE_ELEMENTS
        uint8_t n_bytes, elements_len;
        if (!buffer_read_u8(&dispatcher_context->read_buffer, &n_bytes)
            || !buffer_read_u8(&dispatcher_context->read_buffer, &elements_len)
            || !buffer_can_read(&dispatcher_context->read_buffer, (size_t)n_bytes * elements_len))
        {
            return -7;
        }

        if (elements_len != 1) {
            PRINTF("Elements should be single bytes\n");
            return -8;
        }

        if (n_bytes > bytes_remaining) {
            PRINTF("Received more bytes than expected.\n");
            return -9;
        }

        // update hash
        crypto_hash_update(&hash_context.header,
                           dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset,
                           n_bytes);

        // write bytes to output
        buffer_write_bytes(&out_buffer, data_ptr, n_bytes);

        bytes_remaining -= n_bytes;
    }

    uint8_t computed_hash[20];

    crypto_hash_digest(&hash_context.header, computed_hash, 20);

    if (memcmp(computed_hash, hash, 20) != 0) {
        PRINTF("Hash mismatch.\n");
        return -10;
    }

    return (int)(preimage_len - 1);
}