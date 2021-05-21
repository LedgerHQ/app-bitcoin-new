#include "string.h"

#include "stream_preimage.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../crypto.h"
#include "../../constants.h"
#include "../client_commands.h"

static void process_get_preimage_response(dispatcher_context_t *dc);
static void check_if_done(dispatcher_context_t *dc);
static void receive_more_data(dispatcher_context_t *dc);
static void verify_hash(dispatcher_context_t *dc);


void flow_stream_preimage(dispatcher_context_t *dc) {
    stream_preimage_state_t *state = (stream_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    cx_ripemd160_init(&state->hash_context);

    uint8_t req[1 + 20];
    req[0] = CCMD_GET_PREIMAGE;
    memcpy(&req[1], state->hash, 20);

    dc->next(process_get_preimage_response);
    dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);
}


static void process_get_preimage_response(dispatcher_context_t *dc) {
    stream_preimage_state_t *state = (stream_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint64_t preimage_len;

    uint8_t partial_data_len;

    if (!buffer_read_varint(&dc->read_buffer, &preimage_len)
        || !buffer_read_u8(&dc->read_buffer, &partial_data_len)
        || !buffer_can_read(&dc->read_buffer, partial_data_len))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (partial_data_len > preimage_len) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint8_t *data_ptr = dc->read_buffer.ptr + dc->read_buffer.offset;

    // update hash
    crypto_hash_update(&state->hash_context.header, data_ptr, partial_data_len);

    // call callback with data
    buffer_t buf = buffer_create(data_ptr, partial_data_len);
    dc->run_callback(state->callback, &buf);

    state->bytes_remaining = (size_t)preimage_len - partial_data_len;

    dc->next(check_if_done);
}


static void check_if_done(dispatcher_context_t *dc) {
    stream_preimage_state_t *state = (stream_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->bytes_remaining == 0) {
        dc->next(verify_hash);
    } else {
        uint8_t req[] = { CCMD_GET_MORE_ELEMENTS };
        dc->next(receive_more_data);
        dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);
    }
}


static void receive_more_data(dispatcher_context_t *dc) {
    stream_preimage_state_t *state = (stream_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Parse response to CCMD_GET_MORE_ELEMENTS
    uint8_t n_bytes, elements_len;
    if (!buffer_read_u8(&dc->read_buffer, &n_bytes)
        || !buffer_read_u8(&dc->read_buffer, &elements_len)
        || !buffer_can_read(&dc->read_buffer, (size_t)n_bytes * elements_len))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (elements_len != 1) {
        PRINTF("Elements should be single bytes\n");
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (n_bytes > state->bytes_remaining) {
        PRINTF("Received more bytes than expected.\n");
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint8_t *data_ptr = dc->read_buffer.ptr + dc->read_buffer.offset;

    // update hash
    crypto_hash_update(&state->hash_context.header, data_ptr, n_bytes);

    // call callback with data
    buffer_t buf = buffer_create(data_ptr, n_bytes);
    dc->run_callback(state->callback, &buf);

    state->bytes_remaining -= n_bytes;

    dc->next(check_if_done);
}


static void verify_hash(dispatcher_context_t *dc) {
    stream_preimage_state_t *state = (stream_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t computed_hash[20];

    crypto_hash_digest(&state->hash_context.header, computed_hash, 20);

    if (memcmp(computed_hash, state->hash, 20) != 0) {
        PRINTF("Hash mismatch.\n");
        dc->send_sw(SW_INCORRECT_DATA);
    }

    // all done
}