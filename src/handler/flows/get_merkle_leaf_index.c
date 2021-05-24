#include "string.h"

#include "get_merkle_leaf_index.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"
#include "../../common/merkle.h"
#include "../../constants.h"
#include "../client_commands.h"


int call_get_merkle_leaf_index(dispatcher_context_t *dispatcher_context,
                               size_t size,
                               const uint8_t root[static 20],
                               const uint8_t leaf_hash[static 20])
{
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    uint8_t request[1 + 20 + 20];
    request[0] = CCMD_GET_MERKLE_LEAF_INDEX;
    memcpy(request + 1, root, 20);
    memcpy(request + 1 + 20, leaf_hash, 20);

    if (dispatcher_context->process_interruption(dispatcher_context, request, sizeof(request)) < 0) {
        return -3;
    }

    uint8_t found;
    uint64_t index;

    if (!buffer_read_u8(&dispatcher_context->read_buffer, &found)
        || !buffer_read_varint(&dispatcher_context->read_buffer, &index))
    {
        return -2;
    }

    if (found != 0 && found != 1) {
        return -2;
    }

    if (!found) {
        return -1;
    }

    // Ask the host for the leaf hash with that index
    uint8_t returned_merkle_leaf_hash[20];
    call_get_merkle_leaf_hash(dispatcher_context, root, size, index, returned_merkle_leaf_hash);

    if (memcmp(leaf_hash, returned_merkle_leaf_hash, 20) != 0){
        return -2;
    }

    return index;
}
