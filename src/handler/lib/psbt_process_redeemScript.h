#pragma once

#include "cx.h"

#include "../../boilerplate/dispatcher.h"

#include "../../common/merkle.h"

/**
 * Given a commitment to a merkleized map and a key, this flow parses it as a redeemScript, and verifies that it
 * produces the expected corresponding scriptPubKey.
 * If hash_context is not null, the redeemScript is accumulated in it.
 * At the end of the flow, p2sh_script will contain P2SH(redeemScript).
 *
 * TODO: update docs (not updated from the old subflow format)
 */

int call_psbt_process_redeemScript(dispatcher_context_t *dispatcher_context,
                                   cx_sha256_t *hash_context,
                                   const merkleized_map_commitment_t *map,
                                   const uint8_t *key,
                                   int key_len,
                                   uint8_t p2sh_script[static 23]);