#include "string.h"

#include "get_merkleized_map_value.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../constants.h"

static void receive_index(dispatcher_context_t *dc);
static void receive_value(dispatcher_context_t *dc);


void flow_get_merkleized_map_value(dispatcher_context_t *dc) {
    get_merkleized_map_value_state_t *state = (get_merkleized_map_value_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    merkle_compute_element_hash(state->key, state->key_len, state->key_merkle_hash);

    call_get_merkle_leaf_index(dc, &state->subcontext.get_merkle_leaf_index, receive_index,
                               state->map->size,
                               state->map->keys_root,
                               state->key_merkle_hash);
}


static void receive_index(dispatcher_context_t *dc) {
    get_merkleized_map_value_state_t *state = (get_merkleized_map_value_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (!state->subcontext.get_merkle_leaf_index.found) {
        PRINTF("Key not found.");
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    int index = state->subcontext.get_merkle_leaf_index.index;
    call_get_merkle_leaf_element(dc, &state->subcontext.get_merkle_leaf_element, receive_value,
                                 state->map->values_root,
                                 state->map->size,
                                 index,
                                 state->out,
                                 state->out_len);
}

static void receive_value(dispatcher_context_t *dc) {
    get_merkleized_map_value_state_t *state = (get_merkleized_map_value_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // all done
    state->value_len = state->subcontext.get_merkle_leaf_element.element_len;
}