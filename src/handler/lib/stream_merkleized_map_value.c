#include "stream_merkleized_map_value.h"
#include "get_merkle_leaf_index.h"
#include "stream_merkle_leaf_element.h"

int call_stream_merkleized_map_value(dispatcher_context_t *dispatcher_context,
                                     const merkleized_map_commitment_t *map,
                                     const uint8_t *key,
                                     int key_len,
                                     void (*len_callback)(size_t, void *),
                                     void (*callback)(buffer_t *, void *),
                                     void *callback_state) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    uint8_t key_merkle_hash[32];
    merkle_compute_element_hash(key, key_len, key_merkle_hash);

    int index =
        call_get_merkle_leaf_index(dispatcher_context, map->size, map->keys_root, key_merkle_hash);

    if (index < 0) {
        PRINTF("Key not found, or incorrect data.\n");
        return -1;
    }

    return call_stream_merkle_leaf_element(dispatcher_context,
                                           map->values_root,
                                           map->size,
                                           index,
                                           len_callback,
                                           callback,
                                           callback_state);
}
