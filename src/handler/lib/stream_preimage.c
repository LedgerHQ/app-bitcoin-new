#include <string.h>

#include "../../boilerplate/sw.h"
#include "stream_preimage.h"

#include "../../crypto.h"
#include "../client_commands.h"


int call_stream_preimage(dispatcher_context_t *dispatcher_context,
                         const uint8_t hash[static 20],
                         dispatcher_callback_descriptor_t callback) {

    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    { // free memory as soon as possible
        uint8_t get_preimage_req[1 + 20];
        get_preimage_req[0] = CCMD_GET_PREIMAGE;
        memcpy(&get_preimage_req[1], hash, 20);
        dispatcher_context->set_response(get_preimage_req, sizeof(get_preimage_req), SW_INTERRUPTED_EXECUTION);
    }

    if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
        return -1;
    }

    uint64_t preimage_len_u64;

    uint8_t partial_data_len;

    if (!buffer_read_varint(&dispatcher_context->read_buffer, &preimage_len_u64)
        || !buffer_read_u8(&dispatcher_context->read_buffer, &partial_data_len)
        || !buffer_can_read(&dispatcher_context->read_buffer, partial_data_len))
    {
        return -2;
    }
    uint32_t preimage_len = (uint32_t)preimage_len_u64;

    if (partial_data_len > preimage_len) {
        return -3;
    }

    uint8_t *data_ptr = dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;


    cx_ripemd160_t hash_context;
    cx_ripemd160_init(&hash_context);
    // update hash
    crypto_hash_update(&hash_context.header, data_ptr, partial_data_len);

    // call callback with data
    // TODO: can we use a regular C-style callback here?
    buffer_t buf = buffer_create(data_ptr, partial_data_len);
    dispatcher_context->run_callback(callback, &buf);

    size_t bytes_remaining = (size_t)preimage_len - partial_data_len;

    while (bytes_remaining > 0) {
        uint8_t get_more_elements_req[] = { CCMD_GET_MORE_ELEMENTS };
        dispatcher_context->set_response(get_more_elements_req, sizeof(get_more_elements_req), SW_INTERRUPTED_EXECUTION);
        if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
            return -4;
        }

        // Parse response to CCMD_GET_MORE_ELEMENTS
        uint8_t n_bytes, elements_len;
        if (!buffer_read_u8(&dispatcher_context->read_buffer, &n_bytes)
            || !buffer_read_u8(&dispatcher_context->read_buffer, &elements_len)
            || !buffer_can_read(&dispatcher_context->read_buffer, (size_t)n_bytes * elements_len))
        {
            return -5;
        }

        if (elements_len != 1) {
            PRINTF("Elements should be single bytes\n");
            return -6;
        }

        if (n_bytes > bytes_remaining) {
            PRINTF("Received more bytes than expected.\n");
            return -7;
        }

        uint8_t *data_ptr = dispatcher_context->read_buffer.ptr + dispatcher_context->read_buffer.offset;

        // update hash
        crypto_hash_update(&hash_context.header, data_ptr, n_bytes);

        // call callback with data
        buffer_t buf = buffer_create(data_ptr, n_bytes);
        dispatcher_context->run_callback(callback, &buf);

        bytes_remaining -= n_bytes;
    }

    uint8_t computed_hash[20];

    crypto_hash_digest(&hash_context.header, computed_hash, 20);

    if (memcmp(computed_hash, hash, 20) != 0) {
        PRINTF("Hash mismatch.\n");
        return -5;
    }

    return (int)preimage_len;
}


