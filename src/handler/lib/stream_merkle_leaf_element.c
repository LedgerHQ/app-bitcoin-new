
#include "stream_merkle_leaf_element.h"

#include "get_merkle_leaf_hash.h"
#include "stream_preimage.h"

int call_stream_merkle_leaf_element(dispatcher_context_t *dispatcher_context,
                                    const uint8_t merkle_root[static 32],
                                    uint32_t tree_size,
                                    uint32_t leaf_index,
                                    void (*len_callback)(size_t, void *),
                                    void (*callback)(buffer_t *, void *),
                                    void *callback_state) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    uint8_t leaf_hash[32];
    int res = call_get_merkle_leaf_hash(dispatcher_context,
                                        merkle_root,
                                        tree_size,
                                        leaf_index,
                                        leaf_hash);
    if (res < 0) {
        return -1;
    }

    return call_stream_preimage(dispatcher_context,
                                leaf_hash,
                                len_callback,
                                callback,
                                callback_state);
}
