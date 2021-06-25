#include <string.h>

#include "get_merkle_leaf_hash.h"

#include "../../common/buffer.h"
#include "../../common/write.h"
#include "../../common/merkle.h"
#include "../../boilerplate/sw.h"
#include "../client_commands.h"

// Reads the inputs and sends the GET_MERKLE_LEAF_PROOF request.
int call_get_merkle_leaf_hash(dispatcher_context_t *dc,
                              const uint8_t merkle_root[static 20],
                              uint32_t tree_size,
                              uint32_t leaf_index,
                              uint8_t out[static 20]) {

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    { // make sure memory is deallocated as soon as possible
        uint8_t req[1 + 20 + 4 + 4];
        req[0] = CCMD_GET_MERKLE_LEAF_PROOF;

        memcpy(&req[1], merkle_root, 20);

        write_u32_be(req, 1 + 20, tree_size);
        write_u32_be(req, 1 + 20 + 4, leaf_index);

        dc->set_response(req, sizeof(req), SW_INTERRUPTED_EXECUTION);
    }

    if (dc->process_interruption(dc) < 0) {
        return -1;
    }

    {
        uint8_t proof_size;
        int cur_step;         // counter for the proof steps
        uint8_t cur_hash[20]; // temporary buffer for intermediate hashes
        uint8_t n_proof_elements;
        if (!buffer_read_bytes(&dc->read_buffer, cur_hash, 20)
            || !buffer_read_u8(&dc->read_buffer, &proof_size)
            || !buffer_read_u8(&dc->read_buffer, &n_proof_elements))
        {
            return -2;
        }

        if (n_proof_elements > proof_size) {
            PRINTF("Received more proof data than expected.\n");

            // Wrong length of the Merkle proof.
            return -3;
        }

        if (!buffer_can_read(&dc->read_buffer, 20 * (size_t)n_proof_elements)) {
            return -4;
        }

        // Copy leaf hash to output (although it is not verified yet)
        memcpy(out, cur_hash, 20);

        // Initialize proof verification
        cur_step = 0;

        while (true) {
            int end_step = cur_step + n_proof_elements;
            for ( ; cur_step < end_step; cur_step++) {
                // we use the memory in the buffer directly, to avoid copying the hash unnecessarily
                const uint8_t *sibling_hash = dc->read_buffer.ptr + dc->read_buffer.offset;

                int i = proof_size - cur_step - 1;
                int direction = merkle_get_ith_direction(tree_size, leaf_index, i);

                if (direction == 0) {
                    merkle_combine_hashes(cur_hash, sibling_hash, cur_hash);
                } else if (direction == 1) {
                    merkle_combine_hashes(sibling_hash, cur_hash, cur_hash);
                } else {
                    return -5; // unexpected, proof too long?
                }

                buffer_seek_cur(&dc->read_buffer, 20); // consume the bytes of the sibling hash
            }

            if (cur_step == proof_size) {
                break;
            }

            uint8_t req_more[] = { CCMD_GET_MORE_ELEMENTS };
            dc->set_response(req_more, sizeof(req_more), SW_INTERRUPTED_EXECUTION);
            if (dc->process_interruption(dc) < 0) {
                return -6;
            }

            // Parse response to CCMD_GET_MORE_ELEMENTS
            uint8_t elements_len;
            if (!buffer_read_u8(&dc->read_buffer, &n_proof_elements)
                || !buffer_read_u8(&dc->read_buffer, &elements_len)
                || !buffer_can_read(&dc->read_buffer, (size_t)n_proof_elements * elements_len))
            {
                return -7;
            }

            if (elements_len != 20) {
                return -8;
            }

            if (cur_step + n_proof_elements > proof_size) {
                // Receiving more data then expected
                return -9;
            }
        }

        if (memcmp(merkle_root, cur_hash, 20) != 0) {
            PRINTF("Merkle root mismatch");
            return -10;
        }
    }

    return 0;
}
