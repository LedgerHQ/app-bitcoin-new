#include <stdint.h>
#include <string.h>

#include "compare_wallet_script_at_path.h"

#include "../lib/get_merkleized_map_value.h"
#include "../lib/policy.h"

#include "../../common/read.h"

int compare_wallet_script_at_path(dispatcher_context_t *dispatcher_context,
                                  uint32_t change,
                                  uint32_t address_index,
                                  const policy_node_t *policy,
                                  int wallet_version,
                                  const uint8_t keys_merkle_root[static 32],
                                  uint32_t n_keys,
                                  const uint8_t expected_script[],
                                  size_t expected_script_len) {
    LOG_PROCESSOR(__FILE__, __LINE__, __func__);

    // derive wallet's scriptPubKey, check if it matches the expected one
    uint8_t wallet_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    int wallet_script_len =
        get_wallet_script(dispatcher_context,
                          policy,
                          &(wallet_derivation_info_t){.wallet_version = wallet_version,
                                                      .keys_merkle_root = keys_merkle_root,
                                                      .n_keys = n_keys,
                                                      .change = change,
                                                      .address_index = address_index},
                          wallet_script);
    if (wallet_script_len < 0) {
        PRINTF("Failed to get wallet script\n");
        return -1;  // shouldn't happen
    }

    if (wallet_script_len == (int) expected_script_len &&
        memcmp(wallet_script, expected_script, expected_script_len) == 0) {
        return 1;
    } else {
        return 0;
    }
}
