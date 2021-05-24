#include "string.h"

#include "stream_merkle_leaf_element.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../crypto.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"


/**
 * This flow requests a leaf hash from the Merkle tree, then it requests and verifies its preimage
 */
void flow_stream_merkle_leaf_element(dispatcher_context_t *dc) {
    stream_merkle_leaf_element_state_t *state = (stream_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    call_get_merkle_leaf_hash(dc,
                              state->merkle_root,
                              state->tree_size,
                              state->leaf_index,
                              state->leaf_hash);

    int preimage_len = call_stream_preimage(dc, state->leaf_hash, state->callback);

    if (preimage_len < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    state->element_len = preimage_len;
}
