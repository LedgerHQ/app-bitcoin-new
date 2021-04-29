#include "string.h"

#include "get_merkle_preimage.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../crypto.h"
#include "../../constants.h"
#include "../client_commands.h"

static void check_result(dispatcher_context_t *dc);


static void cb_process_data(get_merkle_preimage_state_t *state, buffer_t *data) {
    if (!state->first_chunk_processed) {
        // On the first batch of data, skip the 0x00 prefix for Merkle leaves
        buffer_seek_cur(data, 1);
        state->first_chunk_processed = true;
    }

    size_t data_size = data->size - data->offset;

    if (!buffer_can_read(&state->out_buffer, data_size)) {
        state->overflow = true;
    } else {
        // TODO: could add a function to buffer.c to pipe bytes cleanly from a buffer to another

        buffer_write_bytes(&state->out_buffer, data->ptr + data->offset, data_size);

        state->preimage_len += data_size;
    }
}

void flow_get_merkle_preimage(dispatcher_context_t *dc) {
    get_merkle_preimage_state_t *state = (get_merkle_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->first_chunk_processed = false;
    state->overflow = false;
    state->preimage_len = 0;

    state->out_buffer = (buffer_t) {
        .ptr = state->out_ptr,
        .offset = 0,
        .size = state->out_ptr_len
    };
    call_stream_preimage(dc, &state->subcontext.stream_preimage, check_result,
                         state->hash,
                         make_callback(state, (dispatcher_callback_t)cb_process_data));
}

// Check if an overflow occurred
static void check_result(dispatcher_context_t *dc) {
    get_merkle_preimage_state_t *state = (get_merkle_preimage_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->overflow) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
    }

    // all done
}