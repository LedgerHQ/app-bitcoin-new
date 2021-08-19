#include <string.h>

#include "get_merkleized_map.h"

#include "get_merkle_leaf_element.h"
#include "check_merkle_tree_sorted.h"

#include "../../common/buffer.h"

int call_get_merkleized_map_with_callback(dispatcher_context_t *dispatcher_context,
                                          const uint8_t root[static 32],
                                          int size,
                                          int index,
                                          dispatcher_callback_descriptor_t keys_callback,
                                          merkleized_map_commitment_t *out_ptr) {
    // LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    uint8_t raw_output[9 + 2 * 32];  // maximum size of serialized result (9 bytes for the varint,
                                     // and the 2 Merkle roots)

    int el_len = call_get_merkle_leaf_element(dispatcher_context,
                                              root,
                                              size,
                                              index,
                                              raw_output,
                                              sizeof(raw_output));
    if (el_len < 0) {
        return -1;
    }

    buffer_t buf = buffer_create(raw_output, el_len);
    if (!buffer_read_varint(&buf, &out_ptr->size) ||
        !buffer_read_bytes(&buf, out_ptr->keys_root, 32) ||
        !buffer_read_bytes(&buf, out_ptr->values_root, 32)) {
        return -1;
    }

    return call_check_merkle_tree_sorted_with_callback(dispatcher_context,
                                                       out_ptr->keys_root,
                                                       out_ptr->size,
                                                       keys_callback);
}