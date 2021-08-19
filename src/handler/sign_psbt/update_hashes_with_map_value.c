
#include "update_hashes_with_map_value.h"

#include "../lib/stream_merkleized_map_value.h"
#include "../../crypto.h"

typedef struct {
    cx_hash_t *hash_unprefixed;
    cx_hash_t *hash_prefixed;
} callback_state_t;

static void cb_process_len(size_t len, void *cb_state) {
    callback_state_t *state = (callback_state_t *) cb_state;

    if (state->hash_prefixed != NULL) {
        crypto_hash_update_varint(state->hash_prefixed, len);
    }
}

static void cb_process_data(buffer_t *data, void *cb_state) {
    callback_state_t *state = (callback_state_t *) cb_state;

    size_t data_len = data->size - data->offset;
    uint8_t *data_start_ptr = data->ptr + data->offset;

    if (state->hash_prefixed != NULL) {
        crypto_hash_update(state->hash_prefixed, data_start_ptr, data_len);
    }
    if (state->hash_unprefixed != NULL) {
        crypto_hash_update(state->hash_unprefixed, data_start_ptr, data_len);
    }
}

int update_hashes_with_map_value(dispatcher_context_t *dispatcher_context,
                                 const merkleized_map_commitment_t *map,
                                 const uint8_t *key,
                                 int key_len,
                                 cx_hash_t *hash_unprefixed,
                                 cx_hash_t *hash_prefixed) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    callback_state_t cb_state = {.hash_unprefixed = hash_unprefixed,
                                 .hash_prefixed = hash_prefixed};

    return call_stream_merkleized_map_value(dispatcher_context,
                                            map,
                                            key,
                                            key_len,
                                            cb_process_len,
                                            cb_process_data,
                                            &cb_state);
}
