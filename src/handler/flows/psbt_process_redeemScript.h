#pragma once

#include "cx.h"

#include "../../boilerplate/dispatcher.h"

#include "../../common/parser.h"

#include "../../constants.h"

#include "stream_merkleized_map_value.h"



typedef struct {
    machine_context_t ctx;

    // inputs/outputs
    const merkleized_map_commitment_t *map;
    const uint8_t *key;
    size_t key_len;
    cx_sha256_t *external_hash_context;
    uint8_t p2sh_script[2 + 20 + 1];

    bool first_call_done;
    cx_sha256_t internal_hash_context;
} psbt_process_redeemScript_state_t;


/**
 * Given a commitment to a merkleized map and a key, this flow parses it as a redeemScript, and verifies that it
 * produces the expected corresponding scriptPubKey.
 * If hash_context is not null, the redeemScript is accumulated in it.
 * At the end of the flow, p2sh_script will contain P2SH(redeemScript).
 */
void flow_psbt_process_redeemScript(dispatcher_context_t *dispatcher_context);


/**
 * Convenience function to call the flow_psbt_process_redeemScript.
 */
static inline void call_psbt_process_redeemScript(dispatcher_context_t *dispatcher_context,
                                                  psbt_process_redeemScript_state_t *flow_state,
                                                  command_processor_t ret_proc,
                                                  cx_sha256_t *hash_context,
                                                  const merkleized_map_commitment_t *map,
                                                  const uint8_t *key,
                                                  int key_len)
{
    flow_state->map = map;
    flow_state->key = key;
    flow_state->key_len = key_len;
    flow_state->external_hash_context = hash_context;

    dispatcher_context->start_flow(
        flow_psbt_process_redeemScript,
        (machine_context_t *)flow_state,
        ret_proc
    );
}
