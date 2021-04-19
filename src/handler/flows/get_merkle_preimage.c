#include "string.h"

#include "get_merkle_preimage.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../crypto.h"
#include "../../constants.h"
#include "../client_commands.h"

static void receive_and_check_preimage(dispatcher_context_t *dc);


void flow_get_merkle_preimage(dispatcher_context_t *dc) {
    flow_get_merkle_preimage_state_t *state = (flow_get_merkle_preimage_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    uint8_t req[1 + 20];
    req[0] = CCMD_GET_PREIMAGE;
    memcpy(&req[1], state->hash, 20);

    dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);

    dc->next(receive_and_check_preimage);
}


static void receive_and_check_preimage(dispatcher_context_t *dc) {
    flow_get_merkle_preimage_state_t *state = (flow_get_merkle_preimage_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    uint8_t preimage_len;
    if (!buffer_read_u8(&dc->read_buffer, &preimage_len)
        || !buffer_can_read(&dc->read_buffer, preimage_len))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    state->preimage_len = preimage_len;

    if (state->out_ptr_len < preimage_len) {
        // output buffer too short
        state->result = false;
        return;
    }

    uint8_t hash[20];
    buffer_read_bytes(&dc->read_buffer, state->out_ptr, preimage_len);

    merkle_compute_element_hash(state->out_ptr, preimage_len, hash);

    state->result = (memcmp(state->hash, hash, 20) == 0);
}