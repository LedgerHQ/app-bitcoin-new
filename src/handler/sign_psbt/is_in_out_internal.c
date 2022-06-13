#include <string.h>

#include "is_in_out_internal.h"
#include "compare_wallet_script_at_path.h"

#include "../../common/script.h"
#include "../../constants.h"

int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                       const sign_psbt_state_t *state,
                       const in_out_info_t *in_out_info,
                       bool is_input) {
    // If we did not find any info about the pubkey associated to the placeholder we're considering,
    // then it's external
    if (!state->cur.in_out.placeholder_found) {
        return 0;
    }

    if (!is_input && state->cur.in_out.is_change != 1) {
        // unlike for inputs, we only consider outputs internal if they are on the change path
        return 0;
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         state->cur.in_out.is_change,
                                         state->cur.in_out.address_index,
                                         &state->wallet_policy_map,
                                         state->wallet_header_version,
                                         state->wallet_header_keys_info_merkle_root,
                                         state->wallet_header_n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}