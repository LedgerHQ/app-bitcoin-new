#include "stdlib.h"
#include "string.h"

#include "psbt_process_redeemScript.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"
#include "../../constants.h"


static void process_redeem_script_callback(psbt_process_redeemScript_state_t *state, buffer_t *data) {
    if (!state->first_call_done) {
        state->first_call_done = true;
        cx_sha256_init(&state->internal_hash_context);

        // skip the 0x00 prefix
        buffer_seek_cur(data, 1);
    }

    size_t data_len = data->size - data->offset;

    crypto_hash_update(&state->internal_hash_context.header, data->ptr + data->offset, data_len);

    if (state->external_hash_context != NULL) {
        crypto_hash_update(&state->external_hash_context->header, data->ptr + data->offset, data_len);
    }
}


void flow_psbt_process_redeemScript(dispatcher_context_t *dc) {
    psbt_process_redeemScript_state_t *state = (psbt_process_redeemScript_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->first_call_done = false; // initialize callback state
    int res = call_stream_merkleized_map_value(dc,
                                               state->map,
                                               state->key,
                                               state->key_len,
                                               make_callback(state, (dispatcher_callback_t)process_redeem_script_callback));
    if (res < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // verify that the computed scriptpubkey is the expected one
    uint8_t script_hash[32];

    crypto_hash_digest(&state->internal_hash_context.header, script_hash, 32);

    state->p2sh_script[0] = 0xa9; // OP_HASH160
    state->p2sh_script[1] = 0x14; // push 20 bytes
    crypto_ripemd160(script_hash, 32, state->p2sh_script + 2);
    state->p2sh_script[2 + 20] = 0x87; // OP_EQUAL
}