#include <stdint.h>
#include <string.h>

#include "compare_wallet_script_at_path.h"

#include "../lib/get_merkleized_map_value.h"
#include "../lib/policy.h"

#include "../../common/read.h"

int compare_wallet_script_at_path(dispatcher_context_t *dispatcher_context,
                                  uint32_t change,
                                  uint32_t address_index,
                                  policy_node_t *policy,
                                  const uint8_t keys_merkle_root[static 32],
                                  uint32_t n_keys,
                                  uint8_t expected_script[],
                                  size_t expected_script_len) {
    LOG_PROCESSOR(dispatcher_context, __FILE__, __LINE__, __func__);

    // derive wallet's scriptPubKey, check if it matches the expected one
    uint8_t wallet_script[MAX_PREVOUT_SCRIPTPUBKEY_LEN];
    buffer_t wallet_script_buf = buffer_create(wallet_script, sizeof(wallet_script));

    int wallet_script_len = call_get_wallet_script(dispatcher_context,
                                                   policy,
                                                   keys_merkle_root,
                                                   n_keys,
                                                   change,
                                                   address_index,
                                                   &wallet_script_buf);
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
