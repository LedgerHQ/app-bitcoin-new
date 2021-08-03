#pragma once

#include "../../boilerplate/dispatcher.h"
#include "../../common/merkle.h"
#include "../../common/wallet.h"

/**
 * TODO
 */
int compare_wallet_script_at_path(dispatcher_context_t *dispatcher_context,
                                  uint32_t change,
                                  uint32_t address_index,
                                  policy_node_t *policy,
                                  const uint8_t keys_merkle_root[static 32],
                                  uint32_t n_keys,
                                  uint8_t expected_script[],
                                  size_t expected_script_len);