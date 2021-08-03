#include <stdlib.h>
#include <string.h>

#include "cx.h"

#include "psbt_parse_rawtx.h"

#include "get_merkleized_map_value_hash.h"
#include "stream_preimage.h"

#include "../../boilerplate/dispatcher.h"
#include "../../boilerplate/sw.h"

#include "../../common/buffer.h"
#include "../../common/parser.h"
#include "../../common/read.h"
#include "../../common/varint.h"
#include "../../crypto.h"


struct parse_rawtx_state_s; // forward declaration

typedef struct {
    struct parse_rawtx_state_s *parent_state; // subparsers can access parent's state
    int scriptsig_size;    // max 10_000 bytes
    int scriptsig_counter; // counter of scriptsig bytes already received
} parse_rawtxinput_state_t;


typedef struct {
    struct parse_rawtx_state_s *parent_state; 
    int scriptpubkey_size;    // max 10_000 bytes
    int scriptpubkey_counter; // counter of scriptpubkey bytes already received
} parse_rawtxoutput_state_t;

typedef struct parse_rawtx_state_s {
    cx_sha256_t *hash_context;

    bool is_segwit;
    int n_inputs;
    int n_outputs;
    int n_witnesses; // only for segwit tx, serialized according to bip-144

    union {
        // since the parsing stages of inputs, outputs and witnesses are disjoint, we reuse the same space in memory
        struct {
            int in_counter;
            parser_context_t input_parser_context;
            parse_rawtxinput_state_t input_parser_state;
        };
        struct {
            int out_counter;
            parser_context_t output_parser_context;
            parse_rawtxoutput_state_t output_parser_state;
        };
        struct {
            int wit_counter;
            int cur_witness_length;
            int cur_witness_bytes_read;
        };
    };

    int output_index;              // index of queried output, or -1

    txid_parser_outputs_t *parser_outputs;

} parse_rawtx_state_t;


typedef struct psbt_parse_rawtx_state_s {
    // internal state
    uint8_t store[32]; // buffer for unparsed data
    int store_data_length; // size of data currently in store

    parse_rawtx_state_t parser_state;
    parser_context_t parser_context;
} psbt_parse_rawtx_state_t;



/*   PARSER FOR A RAWTX INPUT */

// parses the 32-bytes txid of an input in a rawtx
static int parse_rawtxinput_txid(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    uint8_t txid[32];
    bool result = dbuffer_read_bytes(buffers, txid, 32);
    if (result) {
        crypto_hash_update(&state->parent_state->hash_context->header, txid, 32);
    }
    return result;
}

// parses the 4-bytes vout of an input in a rawtx
// TODO: shares logic with the previous method; try to factor out the shared code
static int parse_rawtxinput_vout(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t vout_bytes[4];
    bool result = dbuffer_read_bytes(buffers, vout_bytes, 4);
    if (result) {
        crypto_hash_update(&state->parent_state->hash_context->header, vout_bytes, 4);
    }
    return result;
}

static int parse_rawtxinput_scriptsig_size(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptsig_size;
    bool result = dbuffer_read_varint(buffers, &scriptsig_size);

    if (result) {
        state->scriptsig_size = (int)scriptsig_size;

        crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptsig_size);
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxinput_scriptsig_init(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    (void)buffers;

    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    state->scriptsig_counter = 0;

    return 1;
}

static int parse_rawtxinput_scriptsig(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    while (true) {
        int remaining_len = state->scriptsig_size - state->scriptsig_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
        int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0; // could not read enough data
        }

        crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);

        state->scriptsig_counter += data_len;

        if (state->scriptsig_counter == state->scriptsig_size) {
            return 1; // done
        }
    }
}

static int parse_rawtxinput_sequence(parse_rawtxinput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t sequence_bytes[4];

    bool result = dbuffer_read_bytes(buffers, sequence_bytes, 4);
    if (result) {
        crypto_hash_update(&state->parent_state->hash_context->header, sequence_bytes, 4);
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
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t value_bytes[8];
    bool result = dbuffer_read_bytes(buffers, value_bytes, 8);
    if (result) {
        uint64_t value = read_u64_le(value_bytes, 0);

        crypto_hash_update(&state->parent_state->hash_context->header, value_bytes, 8);

        int relevant_output_index = state->parent_state->output_index;
        if (state->parent_state->out_counter == relevant_output_index) {
            state->parent_state->parser_outputs->vout_value = value;
        }
    }
    return result;
}

static int parse_rawtxoutput_scriptpubkey_size(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint64_t scriptpubkey_size;
    bool result = dbuffer_read_varint(buffers, &scriptpubkey_size);
    if (result) {
        state->scriptpubkey_size = (int)scriptpubkey_size;

        crypto_hash_update_varint(&state->parent_state->hash_context->header, scriptpubkey_size);

        int relevant_output_index = state->parent_state->output_index;
        if (state->parent_state->out_counter == relevant_output_index) {
            state->parent_state->parser_outputs->vout_scriptpubkey_len = (int)scriptpubkey_size;
        }
    }
    return result;
}

// Does not read any bytes; only initializing the state before the next step
static int parse_rawtxoutput_scriptpubkey_init(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    (void)buffers;

    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->scriptpubkey_counter = 0;
    return 1;
}

static int parse_rawtxoutput_scriptpubkey(parse_rawtxoutput_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t data[32];

    while (true) {
        int remaining_len = state->scriptpubkey_size - state->scriptpubkey_counter;

        // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
        int data_len = MIN(32, remaining_len);

        bool read_result = dbuffer_read_bytes(buffers, data, data_len);
        if (!read_result) {
            return 0; // could not read enough data
        }

        crypto_hash_update(&state->parent_state->hash_context->header, data, data_len);

        int relevant_output_index = state->parent_state->output_index;
        int scriptpubkey_len = state->parent_state->parser_outputs->vout_scriptpubkey_len;
        // TODO: handle what happens if scriptpubkey_len > MAX_PREVOUT_SCRIPTPUBKEY_LEN
        if (state->parent_state->out_counter == relevant_output_index && scriptpubkey_len <= MAX_PREVOUT_SCRIPTPUBKEY_LEN) {
            memcpy(state->parent_state->parser_outputs->vout_scriptpubkey + state->scriptpubkey_counter,
                   data,
                   data_len);
        }

        state->scriptpubkey_counter += data_len;

        if (state->scriptpubkey_counter == state->scriptpubkey_size) {
            return 1; // done
        }
    }
}

static const parsing_step_t parse_rawtxoutput_steps[] = {
    (parsing_step_t)parse_rawtxoutput_value,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_size,
    (parsing_step_t)parse_rawtxoutput_scriptpubkey_init, (parsing_step_t)parse_rawtxoutput_scriptpubkey,
};

const int n_parse_rawtxoutput_steps = sizeof(parse_rawtxoutput_steps)/sizeof(parse_rawtxoutput_steps[0]);


/*   PARSER FOR A FULL RAWTX */

static int parse_rawtx_version(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    uint8_t version_bytes[4];

    bool result = dbuffer_read_bytes(buffers, version_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context->header, version_bytes, 4);
    }
    return result;
}


// Checks if this transaction is serialized according to bip144 (segwit), that is, it has a 0x00 marker followed by a
// 0x01 flag where the input count would be expected in the legacy serialization. The marker and flag are read from the
// buffers.
// Does not read any bytes from the buffers if the transaction is in the legacy serialization format.
// The marker and flag (if present) are not added to the hash computation.
static int parse_rawtx_check_segwit(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    if (!dbuffer_can_read(buffers, 1)) {
        return 0;
    }

    // peeks the first byte of the stream, without removing it
    uint8_t first_byte = buffer_can_read(buffers[0], 1) ? buffers[0]->ptr[buffers[0]->offset]
                                                        : buffers[1]->ptr[buffers[1]->offset];

    if (first_byte != 0) {
        state->is_segwit = false;
        return 1; // legacy format, use the legacy parsing scheme
    } else {
        // Segwit format, the first byte is 0x00 and the next should be the 0x01 flag.
        if (!dbuffer_can_read(buffers, 2)) {
            return 0; // need to fetch more data
        }

        uint8_t flag;
        dbuffer_read_u8(buffers, &first_byte); // skip the 0x00 marker
        dbuffer_read_u8(buffers, &flag);
        if (flag != 0x01) {
            PRINTF("Unexpected flag while parsing a segwit transaction: %02x.\n", flag);
            return -1;
        }

        state->is_segwit = true;
        return 1;
    }
}

static int parse_rawtx_input_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove


    uint64_t n_inputs; 
    bool result = dbuffer_read_varint(buffers, &n_inputs);
    if (result) {
        state->n_inputs = (int)n_inputs;

        crypto_hash_update_varint(&state->hash_context->header, n_inputs);
    }
    return result;
}

static int parse_rawtx_inputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void)buffers;

    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    state->in_counter = 0;

    parser_init_context(&state->input_parser_context, &state->input_parser_state);

    state->input_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_inputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->in_counter < state->n_inputs) {
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

        ++state->in_counter;
        parser_init_context(&state->input_parser_context, &state->input_parser_state);
    }
    return 1;
}

static int parse_rawtx_output_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    uint64_t n_outputs; 
    bool result = dbuffer_read_varint(buffers, &n_outputs);
    if (result) {
        state->n_outputs = (int)n_outputs;

        crypto_hash_update_varint(&state->hash_context->header, n_outputs);
    }
    return result;
}

static int parse_rawtx_outputs_init(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    (void)buffers;

    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    state->out_counter = 0;
    parser_init_context(&state->output_parser_context, &state->output_parser_state);

    state->output_parser_state.parent_state = state;
    return 1;
}

static int parse_rawtx_outputs(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove
    while (state->out_counter < state->n_outputs) {
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

        ++state->out_counter;
        parser_init_context(&state->output_parser_context, &state->output_parser_state);
    }
    return 1;
}

static int parse_rawtx_witness_count(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (!state->is_segwit) {
        state->n_witnesses = 0;
        state->wit_counter = 0;

        return 1; // no witnesses to parse
    }

    uint64_t n_witnesses; 
    bool result = dbuffer_read_varint(buffers, &n_witnesses);
    if (result) {
        state->n_witnesses = (int)n_witnesses;
        state->wit_counter = 0;
        state->cur_witness_length = 0;
    }
    return result;
}

// Parses the witness data; currently, no use is made of that data.
static int parse_rawtx_witnesses(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    if (!state->is_segwit) {
        return 1; // no witnesses to parse
    }

    if (state->wit_counter >= state->n_witnesses) {
        return 1; // all witnesses were already parsed
    }

    while (state->wit_counter < state->n_witnesses) {
        // read the witness length if not already read
        if (state->cur_witness_length == 0) {
            // the witness length was not yet read.
            uint64_t cur_witness_length; 
            if (!dbuffer_read_varint(buffers, &cur_witness_length)) {
                return 0; // incomplete, read more data 
            }
            state->cur_witness_length = (int)cur_witness_length;
            state->cur_witness_bytes_read = 0;
        }

        while (state->cur_witness_bytes_read < state->cur_witness_length) {
            uint8_t data[32];
            int remaining_len = state->cur_witness_length - state->cur_witness_bytes_read;

            // We read in chunks of at most 32 bytes, so that we can always interrupt with less than 32 unparsed bytes
            int data_len = MIN(32, remaining_len);
            if (!dbuffer_read_bytes(buffers, data, data_len)) {
                return 0;
            }
            state->cur_witness_bytes_read += data_len;
        }

        // move to parsing the next witness (if any)
        ++state->wit_counter;
        state->cur_witness_length = 0; // reset length to make sure we read the next witness length first
    }
    return 1;
}


static int parse_rawtx_locktime(parse_rawtx_state_t *state, buffer_t *buffers[2]) {
    // PRINTF("%s:%d\t%s\n", __FILE__, __LINE__, __func__); // TODO: remove

    uint8_t locktime_bytes[4];
    bool result = dbuffer_read_bytes(buffers, locktime_bytes, 4);
    if (result) {
        crypto_hash_update(&state->hash_context->header, locktime_bytes, 4);
    }
    return result;
}

static const parsing_step_t parse_rawtx_steps[] = {
    (parsing_step_t)parse_rawtx_version,
    (parsing_step_t)parse_rawtx_check_segwit,
    (parsing_step_t)parse_rawtx_input_count,
    (parsing_step_t)parse_rawtx_inputs_init, (parsing_step_t)parse_rawtx_inputs,
    (parsing_step_t)parse_rawtx_output_count,
    (parsing_step_t)parse_rawtx_outputs_init, (parsing_step_t)parse_rawtx_outputs,
    (parsing_step_t)parse_rawtx_witness_count,
    (parsing_step_t)parse_rawtx_witnesses,
    (parsing_step_t)parse_rawtx_locktime
};

const int n_parse_rawtx_steps = sizeof(parse_rawtx_steps)/sizeof(parse_rawtx_steps[0]);


static void cb_process_data(buffer_t *data, void *cb_state) {
    psbt_parse_rawtx_state_t *state = (psbt_parse_rawtx_state_t *)cb_state;

    buffer_t store_buf = buffer_create(state->store, state->store_data_length);
    buffer_t *buffers[] = { &store_buf, data };

    int result = parser_run(parse_rawtx_steps, n_parse_rawtx_steps, &state->parser_context, buffers, pic);
    if (result == 0) {
        parser_consolidate_buffers(buffers, sizeof(state->store));
        state->store_data_length = store_buf.size;
    } else if (result < 0) {
        // TODO: we might want to process other result values; in order to do so, we might need to change the signature
        //       of callbacks to return a success value (and abort on failures).
        PRINTF("Parser error\n"); // TODO: this should be handled somehow
    }
}

int call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *map,
                          const uint8_t *key,
                          int key_len,
                          int output_index,
                          txid_parser_outputs_t *outputs)
{

    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    cx_sha256_t hash_context;
    cx_sha256_init(&hash_context);

    psbt_parse_rawtx_state_t flow_state;


    // init parser

    flow_state.store_data_length = 0;
    parser_init_context(&flow_state.parser_context, &flow_state.parser_state);

    flow_state.parser_state.output_index = output_index;

    uint8_t value_hash[32];
    int res = call_get_merkleized_map_value_hash(dispatcher_context, map, key, key_len, value_hash);
    if (res < 0) {
        return -1;
    }

    // init the state of the parser (global)
    flow_state.parser_state.hash_context = &hash_context;

    flow_state.parser_state.parser_outputs = outputs;

    res = call_stream_preimage(dispatcher_context, value_hash, NULL, cb_process_data, &flow_state);
    if (res < 0) {
        return -1;
    }

    crypto_hash_digest(&hash_context.header, outputs->txid, 32);
    cx_hash_sha256(outputs->txid, 32, outputs->txid, 32);
    return 0;
}
