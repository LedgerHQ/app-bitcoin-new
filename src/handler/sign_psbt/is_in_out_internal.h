#pragma once

#include "../sign_psbt.h"
#include "../../common/wallet.h"

/**
 * Verifies if a certain input/output is internal (that is, controlled by the wallet being used for
 * signing). This uses the state of sign_psbt and is not meant as a general-purpose function;
 * rather, it avoids some substantial code duplication and removes complexity from sign_psbt.
 *
 * @return 1 if the given input/output is internal; 0 if external; -1 on error.
 */
int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                       const sign_psbt_state_t *state,
                       const in_out_info_t *in_out_info,
                       bool is_input);