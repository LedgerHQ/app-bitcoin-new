#include "string.h"

#include "stream_merkle_leaf_element.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../crypto.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"



static void get_preimage(dispatcher_context_t *dc);
static void finalize_output(dispatcher_context_t *dc);

/**
 * This flow requests a leaf hash from the Merkle tree, then it requests and verifies its preimage
 */
void flow_stream_merkle_leaf_element(dispatcher_context_t *dc) {
    stream_merkle_leaf_element_state_t *state = (stream_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    call_get_merkle_leaf_hash(dc,
                              &state->subcontext.get_merkle_leaf_hash,
                              get_preimage,
                              state->merkle_root,
                              state->tree_size,
                              state->leaf_index);
}


static void get_preimage(dispatcher_context_t *dc) {
    stream_merkle_leaf_element_state_t *state = (stream_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // copy result from the subcontext's memory
    memcpy(state->leaf_hash, state->subcontext.get_merkle_leaf_hash.merkle_leaf, 20);

    call_stream_preimage(dc,
                         &state->subcontext.stream_preimage,
                         finalize_output,
                         state->leaf_hash,
                         state->callback);
}


static void finalize_output(dispatcher_context_t *dc) {
    stream_merkle_leaf_element_state_t *state = (stream_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->element_len = state->subcontext.stream_preimage.preimage_len;
}
