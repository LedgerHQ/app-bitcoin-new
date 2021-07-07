#pragma once

#include "../../boilerplate/dispatcher.h"

#include "cx.h"

#include "../../common/parser.h"

#include "../../constants.h"

#include "../lib/get_merkleized_map_value_hash.h"
#include "../lib/stream_preimage.h"

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


typedef struct {
    uint8_t vout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int vout_scriptpubkey_len;     // will contain the len of the above scriptPubKey
    uint64_t vout_value;           // will contain the value of this output
} txid_parser_outputs_t;

typedef struct parse_rawtx_state_s {
    cx_sha256_t *hash_context;

    bool is_segwit;
    int n_inputs;
    int n_outputs;
    int n_witnesses; // only for segwit tx, serialized according to bip-144

    union {
        // since the parsing stages of inputs and outputs and witnesses are disjoint, we reuse the same space in memory
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

    // parser state, including relevant outputs

    int output_index;              // index of queried output, or -1
    // will contain tx.voud[output_index].scriptPubKey (truncated to 84 bytes if longer)

    txid_parser_outputs_t *parser_outputs;

} parse_rawtx_state_t;


typedef struct psbt_parse_rawtx_state_s {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;

    cx_sha256_t *hash_context;

    // outputs from parsing the transaction 
    txid_parser_outputs_t outputs;

    // internal state
    uint8_t value_hash[20];

    uint8_t store[32]; // buffer for unparsed data
    int store_data_length; // size of data currently in store

    int n_inputs;
    int n_outputs;

    parse_rawtx_state_t parser_state;
    parser_context_t parser_context;
} psbt_parse_rawtx_state_t;


/**
 * Given a commitment to a merkleized map and a key, this flow parses it, computes the transaction hash and
 * computes relevant info about the tx (TODO: which info?)
 */
void flow_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context);


/**
 * Possible flows
 * - Parse the transaction as-is to compute txid
 * - Parse the transaction sighash as described here: https://en.bitcoin.it/wiki/OP_CHECKSIG
 *   - might take the script_code from  
 *  TODO:
 **/



/**
 * Convenience function to call the flow_psbt_parse_rawtx.
 */
static inline void call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                                         psbt_parse_rawtx_state_t *flow_state,
                                         command_processor_t ret_proc,
                                         cx_sha256_t *hash_context,
                                         const merkleized_map_commitment_t *map,
                                         const uint8_t *key,
                                         int key_len,
                                         int output_index)
{
    flow_state->hash_context = hash_context;
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;

    // init parser

    flow_state->store_data_length = 0;
    parser_init_context(&flow_state->parser_context, &flow_state->parser_state);

    flow_state->parser_state.output_index = output_index;

    dispatcher_context->start_flow(
        flow_psbt_parse_rawtx,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
