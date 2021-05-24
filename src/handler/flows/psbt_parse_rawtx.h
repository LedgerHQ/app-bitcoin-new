#pragma once

#include "../../boilerplate/dispatcher.h"

#include "../../common/parser.h"

#include "../../constants.h"

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
        int input_index;               // index of queried input, or -1
        uint8_t prevout_hash[32];      // will contain tx.input[input_index].prevout.hash
        int prevout_n;                 // will contain tx.input[input_index].prevout.n
        uint64_t prevout_value;        // will contain tx.input[input_index].prevout.value

        int output_index;              // index of queried output, or -1
        // will contain tx.voud[output_index].scriptPubKey (truncated to 84 bytes if longer)
        uint8_t vout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
        int vout_scriptpubkey_len;     // will contain the len of the above scriptPubKey
    } compute_txid;

    struct {
        uint32_t sighash_type;
        size_t input_index;
    } compute_sighash_legacy;

    struct {
        uint32_t sighash_type;
        size_t input_index;
        uint32_t nVersion;
        uint8_t hashPrevouts[32];
        uint8_t hashSequence[32];
        // outpoint already known
        // scriptCode not part of the parsing
        uint8_t hashOutputs[32];
        //sighash type


        // We overlap hash contexts that are not used at the same time, in order to save memory
        union {
            struct {
                cx_sha256_t hashPrevouts_context;
                cx_sha256_t hashSequence_context;
            };
            cx_sha256_t hashOutputs_context;
        };
    } compute_sighash_segwit_v0;
} program_state_t;

typedef struct parse_rawtx_state_s {
    ParseMode_t parse_mode;
    cx_sha256_t *hash_context;

    bool is_segwit;
    int n_inputs;
    int n_outputs;
    int n_witnesses; // only for segwit tx, serialized according to bip-144
    uint32_t locktime;


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

    program_state_t *program_state;
} parse_rawtx_state_t;


typedef struct psbt_parse_rawtx_state_s {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;

    ParseMode_t parse_mode;

    cx_sha256_t *hash_context;

    // inputs/outputs specific for the program
    program_state_t program_state;


    // internal state
    uint8_t value_hash[20];

    uint8_t store[32]; // buffer for unparsed data
    int store_data_length; // size of data currently in store

    int n_inputs;
    int n_outputs;

    parse_rawtx_state_t parser_state;
    parser_context_t parser_context;

    union {
        get_merkleized_map_value_hash_state_t get_merkleized_map_value_hash;
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
                                         cx_sha256_t *hash_context,
                                         const merkleized_map_commitment_t *map,
                                         const uint8_t *key,
                                         int key_len,
                                         ParseMode_t parse_mode,
                                         int input_index,
                                         int output_index,
                                         uint32_t sighash_type)
{
    flow_state->hash_context = hash_context;
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;

    flow_state->parse_mode = parse_mode;

    // init parser

    flow_state->store_data_length = 0;
    parser_init_context(&flow_state->parser_context, &flow_state->parser_state);

    if (parse_mode == PARSEMODE_TXID) {
        flow_state->program_state.compute_txid.input_index = input_index;
        flow_state->program_state.compute_txid.output_index = output_index;
    } else if (parse_mode == PARSEMODE_LEGACY_PASS1 || parse_mode == PARSEMODE_LEGACY_PASS2) {
        flow_state->program_state.compute_sighash_legacy.input_index = input_index;
        flow_state->program_state.compute_sighash_legacy.sighash_type = sighash_type;
        // TODO
    } else if (parse_mode == PARSEMODE_SEGWIT_V0) {
        flow_state->program_state.compute_sighash_segwit_v0.input_index = input_index;
        flow_state->program_state.compute_sighash_segwit_v0.sighash_type = sighash_type;
        // TODO
    } else {
        PRINTF("Invoked with wrong program.\n");
    }

    dispatcher_context->start_flow(
        flow_psbt_parse_rawtx,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
