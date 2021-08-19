#include <string.h>

#include "../../boilerplate/sw.h"
#include "get_merkle_leaf_hash.h"

#include "../client_commands.h"

int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 32],
                               const uint8_t leaf_hash[static 32]) {
    // LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    {  // free memory as soon as possible
        uint8_t request[1 + 32 + 32];
        request[0] = CCMD_GET_MERKLE_LEAF_INDEX;
        memcpy(request + 1, root, 32);
        memcpy(request + 1 + 32, leaf_hash, 32);

        SET_RESPONSE(dispatcher_context, request, sizeof(request), SW_INTERRUPTED_EXECUTION);
    }
    if (dispatcher_context->process_interruption(dispatcher_context) < 0) {
        return -3;
    }

    uint8_t found;
    uint64_t index;

    if (!buffer_read_u8(&dispatcher_context->read_buffer, &found) ||
        !buffer_read_varint(&dispatcher_context->read_buffer, &index)) {
        return -1;
    }

    if (found != 0 && found != 1) {
        return -2;
    }

    if (!found) {
        return -3;
    }

    // Ask the host for the leaf hash with that index
    uint8_t returned_merkle_leaf_hash[32];
    int res =
        call_get_merkle_leaf_hash(dispatcher_context, root, size, index, returned_merkle_leaf_hash);
    if (res < 0) {
        return -4;
    }

    if (memcmp(leaf_hash, returned_merkle_leaf_hash, 32) != 0) {
        return -5;
    }

    return index;
}
