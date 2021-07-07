#include <stdlib.h>
#include <string.h>

#include "psbt_process_redeemScript.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../lib/stream_merkleized_map_value.h"

#include "../../common/buffer.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"
#include "../../constants.h"


typedef struct {
    cx_hash_t *internal_hash;
    cx_hash_t *external_hash;
} callback_state_t;

static void process_redeem_script_callback(buffer_t *data, void *state) {
    size_t data_len = data->size - data->offset;

    callback_state_t *cb_state = (callback_state_t *)state;

    crypto_hash_update(cb_state->internal_hash, data->ptr + data->offset, data_len);
    crypto_hash_update(cb_state->external_hash, data->ptr + data->offset, data_len);
}


int call_psbt_process_redeemScript(dispatcher_context_t *dispatcher_context,
                                   cx_sha256_t *hash_context,
                                   const merkleized_map_commitment_t *map,
                                   const uint8_t *key,
                                   int key_len,
                                   uint8_t p2sh_script[static 23])
{

    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    cx_sha256_t internal_hash_context;
    cx_sha256_init(&internal_hash_context);

    callback_state_t cb_state = {
        .internal_hash = &internal_hash_context.header,
        .external_hash = &hash_context->header
    };

    int res = call_stream_merkleized_map_value(dispatcher_context,
                                               map,
                                               key,
                                               key_len,
                                               process_redeem_script_callback,
                                               &cb_state);
    if (res < 0) {
        return -1;
    }

    // verify that the computed scriptpubkey is the expected one
    // TODO: this is broken, not doing what it claims

    uint8_t script_hash[32];

    crypto_hash_digest(&internal_hash_context.header, script_hash, 32);

    p2sh_script[0] = 0xa9; // OP_HASH160
    p2sh_script[1] = 0x14; // push 20 bytes
    crypto_ripemd160(script_hash, 32, p2sh_script + 2);
    p2sh_script[2 + 20] = 0x87; // OP_EQUAL

    return 0;
}