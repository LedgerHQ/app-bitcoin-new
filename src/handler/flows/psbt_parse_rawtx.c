#include "stdlib.h"
#include "string.h"

#include "psbt_parse_rawtx.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"
#include "../../constants.h"

static void init_parsing(dispatcher_context_t *dc);
static void rawtx_parsed(dispatcher_context_t *dc);


/*   PARSER FOR A RAWTX INPUT */

static int parse_rawtxinput_txid(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    uint8_t txid[32];
    bool result = dbuffer_read_bytes(buffers, txid, 32);
    if (result) {
        crypto_hash_update(&state->hash_context_ptr->header, txid, 32);
    }
    return result;
}

static int parse_rawtxinput_vout(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t vout_bytes[4];
    bool result = dbuffer_read_bytes(buffers, vout_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context_ptr->header, vout_bytes, 4);
    }
    return result;
}

static int parse_rawtxinput_scriptsig_size(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptsig_size;
    bool result = dbuffer_read_varint(buffers, &scriptsig_size);
    if (result) {
        uint8_t data[9];
        int data_len = varint_write(data, 0, scriptsig_size);
        crypto_hash_update(&state->hash_context_ptr->header, data, data_len);
        state->scriptsig_size = (int)scriptsig_size;
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxinput_scriptsig_init(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->scriptsig_counter = 0;
    return 1;
}

static int parse_rawtxinput_scriptsig(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    int remaining_len = state->scriptsig_size - state->scriptsig_counter;

    // We read in chunks of at 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
    int data_len = MIN(32, remaining_len);

    bool read_result = dbuffer_read_bytes(buffers, data, data_len);
    if (!read_result) {
        return 0; // could not read enough data
    }

    crypto_hash_update(&state->hash_context_ptr->header, data, data_len);
    state->scriptsig_counter += data_len;

    if (state->scriptsig_counter == state->scriptsig_size) {
        return 1; // done
    } else {
        return 0; // more data to read
    }
}

static int parse_rawtxinput_sequence(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t sequence_bytes[4];
    bool result = dbuffer_read_bytes(buffers, sequence_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context_ptr->header, sequence_bytes, 4);
    }
    return result;
}


static const parsing_step_t parse_rawtxinput_steps[] = {
    (parsing_step_t)parse_rawtxinput_txid,
    (parsing_step_t)parse_rawtxinput_vout,
    (parsing_step_t)parse_rawtxinput_scriptsig_size,
    (parsing_step_t)parse_rawtxinput_scriptsig_init, (parsing_step_t)parse_rawtxinput_scriptsig,
    (parsing_step_t)parse_rawtxinput_sequence,
};

const int n_parse_rawtxinput_steps = sizeof(parse_rawtxinput_steps)/sizeof(parse_rawtxinput_steps[0]);

/*   PARSER FOR A RAWTX OUTPUT */

static int parse_rawtxoutput_value(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t value_bytes[8];
    bool result = dbuffer_read_bytes(buffers, value_bytes, 8);
    if (result) {
        crypto_hash_update(&state->hash_context_ptr->header, value_bytes, 8);
        state->value = read_u64_le(value_bytes, 0);
    }
    return result;
}

static int parse_rawtxoutput_scriptpubkey_size(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptpubkey_size;
    bool result = dbuffer_read_varint(buffers, &scriptpubkey_size);
    if (result) {
        uint8_t data[9];
        int data_len = varint_write(data, 0, scriptpubkey_size);
        crypto_hash_update(&state->hash_context_ptr->header, data, data_len);
        state->scriptpubkey_size = (int)scriptpubkey_size;
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxoutput_scriptpubkey_init(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->scriptpubkey_counter = 0;
    return 1;
}

static int parse_rawtxoutput_scriptpubkey(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    int remaining_len = state->scriptpubkey_size - state->scriptpubkey_counter;

    // We read in chunks of at 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
    int data_len = MIN(32, remaining_len);

    bool read_result = dbuffer_read_bytes(buffers, data, data_len);
    if (!read_result) {
        return 0; // could not read enough data
    }

    crypto_hash_update(&state->hash_context_ptr->header, data, data_len);
    state->scriptpubkey_counter += data_len;

    if (state->scriptpubkey_counter == state->scriptpubkey_size) {
        return 1; // done
    } else {
        return 0; // more data to read
    }
}

static const parsing_step_t parse_rawtxoutput_steps[] = {
    (parsing_step_t)parse_rawtxoutput_value,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_size,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_init, (parsing_step_t)parse_rawtxoutput_scriptpubkey,
};

const int n_parse_rawtxoutput_steps = sizeof(parse_rawtxoutput_steps)/sizeof(parse_rawtxoutput_steps[0]);


/*   PARSER FOR A FULL RAWTX */

static int parse_rawtx_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    // init the general state
    cx_sha256_init(&state->hash_context);

    uint8_t first_byte;
    if (!dbuffer_read_u8(buffers, &first_byte) || first_byte != 0x00) {
        return -1;
    }

    return 1;
}

static int parse_rawtx_version(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t version_bytes[4];
    bool result = dbuffer_read_bytes(buffers, version_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context.header, version_bytes, 4);
    }
    return result;
}

static int parse_rawtx_input_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    bool result = dbuffer_read_u8(buffers, &state->n_inputs);
    if (result) {
        crypto_hash_update_u8(&state->hash_context.header, state->n_inputs);
    }
    return result;
}

static int parse_rawtx_inputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->counter = 0;
    parser_init_context(&state->input_parser_context, &state->input_parser_state);

    state->input_parser_state.hash_context_ptr = &state->hash_context;
    return 1;
}

static int parse_rawtx_inputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->counter < state->n_inputs) {
        while (true) {
            bool result = parser_run(parse_rawtxinput_steps,
                                     n_parse_rawtxinput_steps,
                                     &state->input_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result; // stream exhausted, or error
            } else {
                break; // completed parsing input
            }
        }

        ++state->counter;
        parser_init_context(&state->input_parser_context, &state->input_parser_state);
    }
    return 1;
}

static int parse_rawtx_output_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    bool result = dbuffer_read_u8(buffers, &state->n_outputs);
    if (result) {
        crypto_hash_update_u8(&state->hash_context.header, state->n_outputs);

        state->counter = 0;
        parser_init_context(&state->output_parser_context, &state->output_parser_state);
    }
    return result;
}

static int parse_rawtx_outputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->counter = 0;
    parser_init_context(&state->output_parser_context, &state->output_parser_state);
    state->output_parser_state.hash_context_ptr = &state->hash_context;
    return 1;
}

static int parse_rawtx_outputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->counter < state->n_outputs) {
        while (true) {
            bool result = parser_run(parse_rawtxoutput_steps,
                                     n_parse_rawtxoutput_steps,
                                     &state->output_parser_context,
                                     buffers,
                                     pic);
            if (result != 1) {
                return result; // stream exhausted, or error
            } else {
                break; // completed parsing output
            }
        }

        ++state->counter;
        parser_init_context(&state->output_parser_context, &state->output_parser_state);
    }
    return 1;
}

static int parse_rawtx_locktime(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t value_bytes[4];
    bool result = dbuffer_read_bytes(buffers, value_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context.header, value_bytes, 4);
        state->locktime = read_u32_le(value_bytes, 0);
    }
    return result;
}

static int parse_rawtx_finalize(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    crypto_hash_digest(&state->hash_context.header, state->txid, 32);
    cx_hash_sha256(state->txid, 32, state->txid, 32);

    // reverse txid in-place
    for (int i = 0; i < 16; i++) {
        uint8_t tmp = state->txid[31 - i];
        state->txid[31 - i] = state->txid[i];
        state->txid[i] = tmp;
    }

    return 1;
}

static const parsing_step_t parse_rawtx_steps[] = {
    (parsing_step_t)parse_rawtx_init,
    (parsing_step_t)parse_rawtx_version,
    (parsing_step_t)parse_rawtx_input_count,
    (parsing_step_t)parse_rawtx_inputs_init, (parsing_step_t)parse_rawtx_inputs,
    (parsing_step_t)parse_rawtx_output_count,
    (parsing_step_t)parse_rawtx_outputs_init, (parsing_step_t)parse_rawtx_outputs,
    (parsing_step_t)parse_rawtx_locktime,
    (parsing_step_t)parse_rawtx_finalize,
};

const int n_parse_rawtx_steps = sizeof(parse_rawtx_steps)/sizeof(parse_rawtx_steps[0]);


void flow_psbt_parse_rawtx(dispatcher_context_t *dc) {
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // merkle_compute_element_hash(state->key, state->key_len, state->key_merkle_hash);

    call_get_merkleized_map_value_hash(dc, &state->subcontext.get_merkleized_map_value_hash, init_parsing,
                                       state->map,
                                       state->key,
                                       state->key_len,
                                       state->value_hash);
}


static void cb_process_data(psbt_parse_rawtx_state_t *state, buffer_t *data) {
    buffer_t store_buf = buffer_create(state->store, state->store_data_length);
    buffer_t *buffers[] = { &store_buf, data };

    int result = parser_run(parse_rawtx_steps, n_parse_rawtx_steps, &state->parser_context, buffers, pic);

    if (result == 0) {
        parser_consolidate_buffers(buffers, sizeof(state->store));
        state->store_data_length = store_buf.size;
    }
    // TODO: we might want to process other result values; in order to do so, we might need to change the signature
    //       of callbacks to return a success value (and abort on failures).
}

static void init_parsing(dispatcher_context_t *dc){
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)dc->machine_context_ptr;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    state->store_data_length = 0;
    parser_init_context(&state->parser_context, &state->parser_state);

    call_stream_preimage(dc, &state->subcontext.stream_preimage, rawtx_parsed,
                         state->value_hash,
                         make_callback(state, (dispatcher_callback_t)cb_process_data));
}

static void rawtx_parsed(dispatcher_context_t *dc){
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)dc->machine_context_ptr;
    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    memcpy(state->txid, state->parser_state.txid, 32);
    state->n_inputs = state->parser_state.n_inputs;
    state->n_outputs = state->parser_state.n_outputs;
    // TODO
}
