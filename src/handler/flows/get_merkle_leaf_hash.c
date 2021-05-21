#include "string.h"

#include "get_merkle_leaf_hash.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../crypto.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"


// Reads the inputs and sends the GET_MERKLE_LEAF_PROOF request.
void call_get_merkle_leaf_hash(dispatcher_context_t *dc,
                               const uint8_t merkle_root[static 20],
                               uint32_t tree_size,
                               uint32_t leaf_index,
                               uint8_t out[static 20]) {

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);


    uint8_t cur_hash[20]; // temporary buffer for intermediate hashes
    uint8_t proof_size;
    int cur_step;         // counter for the proof steps

    uint8_t directions[MAX_MERKLE_TREE_DEPTH];

    uint8_t req[1 + 20 + 4 + 4];
    req[0] = CCMD_GET_MERKLE_LEAF_PROOF;

    memcpy(&req[1], merkle_root, 20);

    write_u32_be(req, 1 + 20, tree_size);
    write_u32_be(req, 1 + 20 + 4, leaf_index);

    if (dc->process_interruption(dc, req, sizeof(req)) < 0) {
        return;
    }

    uint8_t n_proof_elements;
    if (!buffer_read_bytes(&dc->read_buffer, cur_hash, 20)
        || !buffer_read_u8(&dc->read_buffer, &proof_size)
        || !buffer_read_u8(&dc->read_buffer, &n_proof_elements))
    {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (n_proof_elements > proof_size) {
        PRINTF("Received more proof data than expected.\n");

        // Wrong length of the Merkle proof.
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_can_read(&dc->read_buffer, 20 * (size_t)n_proof_elements)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Initialize the directions array
    if (merkle_get_directions(tree_size, leaf_index, directions, sizeof(directions)) != proof_size) {
        PRINTF("Proof size is not correct.\n");

        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // Copy leaf hash to output (although it is not verified yet)
    memcpy(out, cur_hash, 20);

    // Initialize proof verification
    cur_step = 0;

    while (true) {
        int end_step = cur_step + n_proof_elements;
        for ( ; cur_step < end_step; cur_step++) {
            uint8_t sibling_hash[20];
            buffer_read_bytes(&dc->read_buffer, sibling_hash, 20);

            int i = proof_size - cur_step - 1;
            if (directions[i] == 0) {
                merkle_combine_hashes(cur_hash, sibling_hash, cur_hash);
            } else {
                merkle_combine_hashes(sibling_hash, cur_hash, cur_hash);
            }
        }

        if (cur_step == proof_size) {
            break;
        }

        uint8_t req_more[] = { CCMD_GET_MORE_ELEMENTS };
        if (dc->process_interruption(dc, req_more, sizeof(req_more)) < 0) {
            return;
        }

        // Parse response to CCMD_GET_MORE_ELEMENTS
        uint8_t elements_len;
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

        if (cur_step + n_proof_elements > proof_size) {
            // Receiving more data then expected
            dc->send_sw(SW_INCORRECT_DATA);
            return;
        }
    }

    if (memcmp(merkle_root, cur_hash, 20) != 0) {
        dc->send_sw(SW_INCORRECT_DATA);
    }
}
