#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../common/wallet.h"
#include "../../handler/sign_psbt/sign_psbt_cache.h"

/**
 * TODO
 */
int compare_wallet_script_at_path(dispatcher_context_t *dispatcher_context,
                                  sign_psbt_cache_t *sign_psbt_cache,
                                  uint32_t change,
                                  uint32_t address_index,
                                  const policy_node_t *policy,
                                  int wallet_version,
                                  const uint8_t keys_merkle_root[static 32],
                                  uint32_t n_keys,
                                  const uint8_t expected_script[],
                                  size_t expected_script_len);