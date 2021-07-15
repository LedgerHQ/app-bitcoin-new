#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/wallet.h"

/**
 * TODO
 */
int call_get_wallet_script(dispatcher_context_t *dispatcher_context,
                           policy_node_t *policy,
                           const uint8_t keys_merkle_root[static 20],
                           uint32_t n_keys,
                           bool change,
                           size_t address_index,
                           buffer_t *out_buf,
                           cx_hash_t *hash_context);
