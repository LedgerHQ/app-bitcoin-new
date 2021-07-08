#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../constants.h"

typedef struct {
    uint64_t vout_value;           // will contain the value of this output
    int vout_scriptpubkey_len;     // will contain the len of the above scriptPubKey
    uint8_t vout_scriptpubkey[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    uint8_t txid[32];
} txid_parser_outputs_t;


/**
 * Given a commitment to a merkleized map and a key, this flow parses it, computes the transaction hash and
 * computes relevant info about the tx (TODO: which info?)
 */
// void flow_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context);


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
int call_psbt_parse_rawtx(dispatcher_context_t *dispatcher_context,
                          const merkleized_map_commitment_t *map,
                          const uint8_t *key,
                          int key_len,
                          int output_index,
                          txid_parser_outputs_t *outputs);
