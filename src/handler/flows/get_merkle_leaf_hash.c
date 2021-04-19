#include "string.h"

#include "get_merkle_leaf_hash.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../crypto.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"

// processors
static void receive_and_check_merkle_proof(dispatcher_context_t *dc);
static void request_more_proof_data(dispatcher_context_t *dc);
static void receive_more_proof_data(dispatcher_context_t *dc);
static void check_root(dispatcher_context_t *dc);

// utility functions
static void process_proof_steps(flow_get_merkle_leaf_hash_state_t *state, buffer_t *read_buffer, size_t n_proof_elements);


// Reads the inputs and sends the GET_MERKLE_LEAF_PROOF request.
void flow_get_merkle_leaf_hash(dispatcher_context_t *dc) {
    flow_get_merkle_leaf_hash_state_t *state = (flow_get_merkle_leaf_hash_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    uint8_t req[1 + 20 + 4 + 4];
    req[0] = CCMD_GET_MERKLE_LEAF_PROOF;
    memcpy(&req[1], state->merkle_root, 20);
    write_u32_be(req, 1 + 20, state->tree_size);
    write_u32_be(req, 1 + 20 + 4, state->leaf_index);

    dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);

    dc->next(receive_and_check_merkle_proof);
}


// Parses the response to the GET_MERKLE_LEAF_PROOF request; process the portion of the received Mekle proof.
static void receive_and_check_merkle_proof(dispatcher_context_t *dc) {
    flow_get_merkle_leaf_hash_state_t *state = (flow_get_merkle_leaf_hash_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    uint8_t proof_size, n_proof_elements;
    if (!buffer_read_bytes(&dc->read_buffer, &state->merkle_leaf, 20)
        || !buffer_read_u8(&dc->read_buffer, &proof_size)
        || !buffer_read_u8(&dc->read_buffer, &n_proof_elements))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (n_proof_elements > proof_size) {
        PRINTF("Received more proof data than expected.");

        // Wrong length of the Merkle proof.
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    state->proof_size = proof_size;

    if (!buffer_can_read(&dc->read_buffer, 20 * (size_t)n_proof_elements)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Initialize the directions array
    if (merkle_get_directions(state->tree_size, state->leaf_index, state->directions, sizeof(state->directions)) != proof_size) {
        PRINTF("Proof size is not correct.");

        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // Initialize other necessary variables to verify the proof
    memcpy(state->cur_hash, state->merkle_leaf, 20);
    state->cur_step = 0;

    process_proof_steps(state, &dc->read_buffer, n_proof_elements);

    dc->next(request_more_proof_data);
}


// Checks if the proof is complete; if not, sends a GET_MORE_ELEMENTS command; otherwise, go to final state.
static void request_more_proof_data(dispatcher_context_t *dc) {
    flow_get_merkle_leaf_hash_state_t *state = (flow_get_merkle_leaf_hash_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    if (state->cur_step == state->proof_size) {
        dc->next(check_root);
    } else {
        uint8_t req[] = { CCMD_GET_MORE_ELEMENTS };
        dc->send_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);
        dc->next(receive_more_proof_data);
    }
}


// Receives and processes additional Merkle proof elements 
static void receive_more_proof_data(dispatcher_context_t *dc) {
    flow_get_merkle_leaf_hash_state_t *state = (flow_get_merkle_leaf_hash_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    uint8_t n_proof_elements, elements_len;
    if (!buffer_read_u8(&dc->read_buffer, &n_proof_elements)
        || !buffer_read_u8(&dc->read_buffer, &elements_len)
        || !buffer_can_read(&dc->read_buffer, (size_t)n_proof_elements * elements_len))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (elements_len != 20) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (state->cur_step + n_proof_elements > state->proof_size) {
        // Receiving more data then expected
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    process_proof_steps(state, &dc->read_buffer, n_proof_elements);

    dc->next(request_more_proof_data);
}


// Once the full Merkle proof is received, sets the result to true if the Merkle root matches, false otherwise.
static void check_root(dispatcher_context_t *dc) {
    flow_get_merkle_leaf_hash_state_t *state = (flow_get_merkle_leaf_hash_state_t *)dc->machine_context_ptr;

    PRINTF("%s %d: %s\n", __FILE__, __LINE__, __func__);

    state->result = (memcmp(state->merkle_root, state->cur_hash, 20) == 0);
}


// Utility function to process a number of steps of the Merkle proof
static void process_proof_steps(flow_get_merkle_leaf_hash_state_t *state, buffer_t *read_buffer, size_t n_proof_elements) {
    int end_step = state->cur_step + n_proof_elements; 
    for ( ; state->cur_step < end_step; state->cur_step++) {
        uint8_t sibling_hash[20];
        buffer_read_bytes(read_buffer, sibling_hash, 20);

        int i = state->proof_size - state->cur_step - 1;
        if (state->directions[i] == 0) {
            merkle_combine_hashes(state->cur_hash, sibling_hash, state->cur_hash);
        } else {
            merkle_combine_hashes(sibling_hash, state->cur_hash, state->cur_hash);
        }
    }
}
