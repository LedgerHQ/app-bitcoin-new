#include "string.h"

#include "get_merkle_leaf_element.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../crypto.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"



static void check_merkle_proof_result(dispatcher_context_t *dc);
static void finalize_output(dispatcher_context_t *dc);

/**
 * This flow requests a leaf hash from the Merkle tree, then it requests and verifies its preimage
 */
void flow_get_merkle_leaf_element(dispatcher_context_t *dc) {
    get_merkle_leaf_element_state_t *state = (get_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    call_get_merkle_leaf_hash(dc,
                              &state->subcontext.get_merkle_leaf_hash,
                              check_merkle_proof_result,
                              state->merkle_root,
                              state->tree_size,
                              state->leaf_index);
}

static void check_merkle_proof_result(dispatcher_context_t *dc) {
    get_merkle_leaf_element_state_t *state = (get_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->subcontext.get_merkle_leaf_hash.result == false) {
        PRINTF("get_merkle_leaf_hash failed!\n");
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    call_get_merkle_preimage(dc,
                             &state->subcontext.get_merkle_preimage,
                             finalize_output,
                             state->subcontext.get_merkle_leaf_hash.merkle_leaf,
                             state->out_ptr,
                             state->out_ptr_len);
}


static void finalize_output(dispatcher_context_t *dc) {
    get_merkle_leaf_element_state_t *state = (get_merkle_leaf_element_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->element_len = state->subcontext.get_merkle_preimage.preimage_len;
    state->result = state->subcontext.get_merkle_preimage.result;
}
