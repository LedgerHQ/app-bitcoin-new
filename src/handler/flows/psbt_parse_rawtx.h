#pragma once

#include "../../boilerplate/dispatcher.h"

#include "../../common/parser.h"

#include "get_merkleized_map_value_hash.h"
#include "stream_preimage.h"

typedef enum {
    PROGRAM_TXID = -2,   // compute txid compute
    PROGRAM_LEGACY = -1, // legacy transaction digest
    PROGRAM_SEGWIT_V0 = 0 // segwit v0 transaction digest
} ProgramType;


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


typedef enum {
    PARSEMODE_TXID,
    PARSEMODE_LEGACY_PASS1,
    PARSEMODE_LEGACY_PASS2,
    PARSEMODE_SEGWIT_V0
} ParseMode_t;

typedef union {
    // We distinguish the state depending on the program, rather than the parse_mode,

    struct {
        size_t input_index; // retrieve prevout.hash and prevout_number of this index
        // TODO
    } compute_txid;

    struct {
        uint32_t sighash_type;
        size_t input_index;
        // TODO
    } compute_sighash_legacy;

    struct {
        uint32_t sighash_type;
        size_t input_index;
        // TODO
    } compute_sighash_segwit_v0;
} program_state_t;

typedef struct parse_rawtx_state_s {
    ParseMode_t parse_mode;
    cx_sha256_t *hash_context;

    uint8_t n_inputs;
    uint8_t n_outputs;
    uint32_t locktime;

    int counter;

    parser_context_t input_parser_context;
    parse_rawtxinput_state_t input_parser_state;

    parser_context_t output_parser_context;
    parse_rawtxoutput_state_t output_parser_state;

    program_state_t *program_state;
} parse_rawtx_state_t;


typedef struct psbt_parse_rawtx_state_s {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;

    ProgramType program;


    cx_sha256_t hash_context;
    uint8_t txhash[32]; // the meaning of this hash is different for different programs

    // inputs/outputs specific for the program
    program_state_t program_state;


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
 * Possible flows
 * - Parse the transaction as-is to compute txid
 * - Parse the transaction sighash as described here: https://en.bitcoin.it/wiki/OP_CHECKSIG
 *   - might take the script_code from  
 * 
 **/



/**
 * Convenience function to call the flow_psbt_parse_rawtx.
 */
static inline void call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                                         psbt_parse_rawtx_state_t *flow_state,
                                         command_processor_t ret_proc,
                                         const merkleized_map_commitment_t *map,
                                         const uint8_t *key,
                                         int key_len,
                                         ProgramType program,
                                         size_t input_index,
                                         uint32_t sighash_type)
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;

    flow_state->program = program;

    // init parser
    cx_sha256_init(&flow_state->hash_context);

    flow_state->store_data_length = 0;
    parser_init_context(&flow_state->parser_context, &flow_state->parser_state);

    if (program == PROGRAM_TXID) {
        // nothing to do
        flow_state->program_state.compute_txid.input_index = input_index;
    } if (program == PROGRAM_LEGACY) {
        flow_state->program_state.compute_sighash_legacy.input_index = input_index;
        flow_state->program_state.compute_sighash_legacy.sighash_type = sighash_type;
        // TODO
    } else if (program == PROGRAM_SEGWIT_V0) {
        flow_state->program_state.compute_sighash_segwit_v0.input_index = input_index;
        flow_state->program_state.compute_sighash_segwit_v0.sighash_type = sighash_type;
        // TODO
    } else {
        PRINTF("Invoked with wrong program.");
    }

    dispatcher_context->start_flow(
        flow_psbt_parse_rawtx,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
