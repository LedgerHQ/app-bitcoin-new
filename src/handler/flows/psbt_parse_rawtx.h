#pragma once

#include "../../boilerplate/dispatcher.h"

#include "../../common/parser.h"

#include "get_merkleized_map_value_hash.h"
#include "stream_preimage.h"

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
    uint64_t value;
} parse_rawtxoutput_state_t;


typedef struct parse_rawtx_state_s {
    uint8_t n_inputs;
    uint8_t n_outputs;
    uint32_t locktime;

    int counter;

    parser_context_t input_parser_context;
    parse_rawtxinput_state_t input_parser_state;

    parser_context_t output_parser_context;
    parse_rawtxoutput_state_t output_parser_state;
    cx_sha256_t hash_context;

    uint8_t *txhash;
} parse_rawtx_state_t;



typedef struct psbt_parse_rawtx_state_s {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;
    uint8_t txhash[32];


    // internal state
    uint8_t value_hash[20];

    uint8_t store[32]; // buffer for unparsed data
    int store_data_length; // size of data currently in store

    uint8_t n_inputs;
    uint8_t n_outputs;

    parse_rawtx_state_t parser_state;
    parser_context_t parser_context;

    union {
        get_merkleized_map_value_hash_state_t get_merkleized_map_value_hash;
        stream_preimage_state_t stream_preimage;
    } subcontext;
} psbt_parse_rawtx_state_t;


/**
 * Given a commitment to a merkleized map and a key, this flow parses it, computes the transaction hash and
 * computes relevant info about the tx (TODO: which info?)
 */
void flow_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the call_get_merkleized_map flow.
 */
static inline void call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                                         psbt_parse_rawtx_state_t *flow_state,
                                         command_processor_t ret_proc,
                                         const merkleized_map_commitment_t *map,
                                         const uint8_t *key,
                                         int key_len)
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;

    dispatcher_context->start_flow(
        flow_psbt_parse_rawtx,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
