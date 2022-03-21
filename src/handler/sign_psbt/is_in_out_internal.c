#include <string.h>

#include "is_in_out_internal.h"
#include "compare_wallet_script_at_path.h"
#include "get_fingerprint_and_path.h"

#include "../../common/bip32.h"
#include "../../common/psbt.h"
#include "../../common/script.h"
#include "../../constants.h"

extern global_context_t *G_coin_config;

int is_in_out_internal(dispatcher_context_t *dispatcher_context,
                       const sign_psbt_state_t *state,
                       const in_out_info_t *in_out_info,
                       bool is_input) {
    if (!in_out_info->has_bip32_derivation) {
        PRINTF("No BIP32 derivation\n");
        return 0;
    }

    // get path, obtain change and address_index,
    int bip32_path_len;
    uint32_t bip32_path[MAX_BIP32_PATH_STEPS];
    uint32_t fingerprint;

    int script_type = get_script_type(in_out_info->scriptPubKey, in_out_info->scriptPubKey_len);
    if (script_type == -1) {
        // OP_RETURN outputs would return -1 despite being valid; but for those, there shouldn't be
        // any BIP32 derivation in the PSBT, so no special case is needed here.

        PRINTF("Invalid script type\n");
        return -1;
    } else if (script_type == SCRIPT_TYPE_UNKNOWN_SEGWIT) {
        // An unknown but valid segwit script type, definitely external.
        return 0;
    } else if (script_type == SCRIPT_TYPE_P2TR) {
        // taproot output, use PSBT_{IN,OUT}_TAP_BIP32_DERIVATION
        uint8_t key[1 + 32];
        key[0] = is_input ? PSBT_IN_TAP_BIP32_DERIVATION : PSBT_OUT_TAP_BIP32_DERIVATION;
        memcpy(key + 1, in_out_info->bip32_derivation_pubkey, 32);

        bip32_path_len = get_emptyhashes_fingerprint_and_path(dispatcher_context,
                                                              &in_out_info->map,
                                                              key,
                                                              sizeof(key),
                                                              &fingerprint,
                                                              bip32_path);
    } else {
        // legacy or segwitv0 output, use PSBT_OUT_BIP32_DERIVATION
        uint8_t key[1 + 33];
        key[0] = is_input ? PSBT_IN_BIP32_DERIVATION : PSBT_OUT_BIP32_DERIVATION;
        memcpy(key + 1, in_out_info->bip32_derivation_pubkey, 33);

        bip32_path_len = get_fingerprint_and_path(dispatcher_context,
                                                  &in_out_info->map,
                                                  key,
                                                  sizeof(key),
                                                  &fingerprint,
                                                  bip32_path);
    }

    if (bip32_path_len < 0) {
        PRINTF("Could not get BIP32 path\n");
        return -1;
    }

    // As per wallet policy assumptions, the path must have change and address index
    if (bip32_path_len < 2) {
        PRINTF("BIP32 path too short\n");
        return 0;
    }
    uint32_t change = bip32_path[bip32_path_len - 2];
    uint32_t address_index = bip32_path[bip32_path_len - 1];

    if (!is_input && change != 1) {
        // unlike for inputs, change must be 1 for this output to be considered internal
        return 0;
    }

    if (state->is_wallet_canonical) {
        // for canonical wallets, the path must be exactly as expected for a change output
        uint32_t coin_types[2] = {G_coin_config->bip44_coin_type, G_coin_config->bip44_coin_type2};
        if (!is_address_path_standard(bip32_path,
                                      bip32_path_len,
                                      state->bip44_purpose,
                                      coin_types,
                                      2,
                                      is_input ? -1 : 1)) {
            return 0;
        }
    }

    return compare_wallet_script_at_path(dispatcher_context,
                                         change,
                                         address_index,
                                         &state->wallet_policy_map,
                                         state->wallet_header_keys_info_merkle_root,
                                         state->wallet_header_n_keys,
                                         in_out_info->scriptPubKey,
                                         in_out_info->scriptPubKey_len);
}