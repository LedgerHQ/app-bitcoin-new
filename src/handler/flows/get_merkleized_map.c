#include "string.h"

#include "get_merkleized_map.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../constants.h"

static void receive_and_check_preimage(dispatcher_context_t *dc);


void flow_get_merkleized_map(dispatcher_context_t *dc) {
    get_merkleized_map_state_t *state = (get_merkleized_map_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    call_get_merkle_leaf_element(dc, &state->subcontext.get_merkle_leaf_element, receive_and_check_preimage,
                                state->root,
                                state->size,
                                state->index,
                                state->raw_output,
                                sizeof(state->raw_output));
}


static void receive_and_check_preimage(dispatcher_context_t *dc) {
    get_merkleized_map_state_t *state = (get_merkleized_map_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    buffer_t buf = {
        .ptr = state->raw_output,
        .offset = 0,
        .size = state->subcontext.get_merkle_leaf_element.element_len
    };

    if (!buffer_read_varint(&buf, &state->out_ptr->size)
        || !buffer_read_bytes(&buf, state->out_ptr->keys_root, 20)
        || !buffer_read_bytes(&buf, state->out_ptr->values_root, 20))
    {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    call_check_merkle_tree_sorted(dc, &state->subcontext.check_merkle_tree_sorted, NULL,
                                  state->out_ptr->keys_root,
                                  state->out_ptr->size);
}