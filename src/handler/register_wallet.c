/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

#include "os.h"
#include "cx.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/merkle.h"
#include "../common/read.h"
#include "../common/wallet.h"
#include "../common/write.h"

#include "../commands.h"
#include "../constants.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "lib/policy.h"

#include "client_commands.h"

#include "register_wallet.h"

static void process_cosigner_info(dispatcher_context_t *dc);
static void next_cosigner(dispatcher_context_t *dc);
static void finalize_response(dispatcher_context_t *dc);

extern global_context_t *G_coin_config;

static bool is_policy_acceptable(const policy_node_t *policy);
static bool is_policy_name_acceptable(const char *name, size_t name_len);

/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in
 * it.
 */
void handler_register_wallet(dispatcher_context_t *dc, uint8_t p2) {
    (void) p2;

    register_wallet_state_t *state = (register_wallet_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        SEND_SW(dc, SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint64_t serialized_policy_map_len;
    if (!buffer_read_varint(&dc->read_buffer, &serialized_policy_map_len)) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    if (serialized_policy_map_len > MAX_POLICY_MAP_SERIALIZED_LENGTH) {
        PRINTF("Policy map too long\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if ((read_policy_map_wallet(&dc->read_buffer, &state->wallet_header)) < 0) {
        PRINTF("Failed reading policy map\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    buffer_t policy_map_buffer =
        buffer_create(&state->wallet_header.policy_map, state->wallet_header.policy_map_len);
    if (parse_policy_map(&policy_map_buffer,
                         state->policy_map_bytes,
                         sizeof(state->policy_map_bytes)) < 0) {
        PRINTF("Failed parsing policy map\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // Compute the wallet id (sha256 of the serialization)
    get_policy_wallet_id(&state->wallet_header, state->wallet_id);

    // Verify that the name is acceptable
    if (!is_policy_name_acceptable(state->wallet_header.name, state->wallet_header.name_len)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // check if policy is acceptable; only multisig is accepted at this time,
    // and it must be one of the accepted patterns.
    if (!is_policy_acceptable(&state->policy_map)) {
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    state->master_key_fingerprint = crypto_get_master_key_fingerprint();

    state->next_pubkey_index = 0;

    ui_display_wallet_header(dc, &state->wallet_header, process_cosigner_info);
}

/**
 * Receives and parses the next pubkey info.
 * Asks the user to validate the pubkey info.
 */
static void process_cosigner_info(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    int pubkey_info_len = call_get_merkle_leaf_element(dc,
                                                       state->wallet_header.keys_info_merkle_root,
                                                       state->wallet_header.n_keys,
                                                       state->next_pubkey_index,
                                                       state->next_pubkey_info,
                                                       MAX_POLICY_KEY_INFO_LEN);

    if (pubkey_info_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    state->next_pubkey_info[pubkey_info_len] = 0;

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = buffer_create(state->next_pubkey_info, pubkey_info_len);

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
        PRINTF("Incorrect policy map.\n");
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    // We refuse to register wallets without key origin information, or whose keys don't end with
    // the wildcard ('/**'). The key origin information is necessary when signing to identify which
    // one is our key. Using addresses without a wildcard could potentially be supported, but
    // disabled for now (question to address: can only _some_ of the keys have a wildcard?).

    if (!key_info.has_key_origin) {
        PRINTF("Key info without origin unsupported.\n");
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    if (!key_info.has_wildcard) {
        PRINTF("Key info without wildcard unsupported.\n");
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    bool is_key_internal = false;
    if (read_u32_be(key_info.master_key_fingerprint, 0) == state->master_key_fingerprint) {
        // it could be a collision on the fingerprint; we verify that we can actually generate the
        // same pubkey
        char pubkey_derived[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
        int serialized_pubkey_len =
            get_serialized_extended_pubkey_at_path(key_info.master_key_derivation,
                                                   key_info.master_key_derivation_len,
                                                   G_coin_config->bip32_pubkey_version,
                                                   pubkey_derived);
        if (serialized_pubkey_len == -1) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }

        if (strncmp(key_info.ext_pubkey, pubkey_derived, MAX_SERIALIZED_PUBKEY_LENGTH) == 0) {
            is_key_internal = true;
            ++state->n_internal_keys;
        }
    }

    // TODO: it would be sensible to validate the pubkey (at least syntactically + validate
    // checksum)
    //       Currently we are showing to the user whichever string is passed by the host.

    ui_display_policy_map_cosigner_pubkey(dc,
                                          (char *) state->next_pubkey_info,
                                          state->next_pubkey_index,  // 1-indexed for the UI
                                          state->wallet_header.n_keys,
                                          is_key_internal,
                                          next_cosigner);
}

static void next_cosigner(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    ++state->next_pubkey_index;
    if (state->next_pubkey_index < state->wallet_header.n_keys) {
        dc->next(process_cosigner_info);
    } else {
        dc->next(finalize_response);
    }
}

static void finalize_response(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *) &G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    if (state->n_internal_keys != 1) {
        // Unclear if there is any use case for multiple internal keys in the same wallet.
        // We disallow that, might reconsider in future versions if needed.
        SEND_SW(dc, SW_NOT_SUPPORTED);
        return;
    }

    // TODO: force PIN validation to prevent evil maid attacks registering a wallet.
    //       As only the wallet name is shown when signing from a registered wallet, registering a
    //       wallet is a sensitive operation, and a fraudulent wallet with the same name would
    //       result in loss of funds.

    struct {
        uint8_t wallet_id[32];
        uint8_t hmac[32];
    } response;

    memcpy(response.wallet_id, state->wallet_id, sizeof(state->wallet_id));

    // TODO: we might want to add external info to be committed with the signature (e.g.: app
    // version).
    //       This would allow newer versions of the app to invalidate an old signature if desired,
    //       for example if a vulnerability is discovered in the registration flow of a previous
    //       app. The response would be changed to:
    //         <wallet_id> <metadata_len> <metadata> <hmac>
    //       And the signature would be on the concatenation of the wallet id and the metadata.
    //       The client must persist the metadata, together with the signature.

    // sign wallet id and produce response
    uint8_t key[32];

    BEGIN_TRY {
        TRY {
            crypto_derive_symmetric_key(WALLET_SLIP0021_LABEL, WALLET_SLIP0021_LABEL_LEN, key);

            cx_hmac_sha256(key,
                           sizeof(key),
                           state->wallet_id,
                           sizeof(state->wallet_id),
                           response.hmac,
                           sizeof(response.hmac));
        }
        FINALLY {
            explicit_bzero(key, sizeof(key));
        }
    }
    END_TRY;

    SEND_RESPONSE(dc, &response, sizeof(response), SW_OK);
}

static bool is_policy_acceptable(const policy_node_t *policy) {
    // TODO: might want to add more restrictions

    return policy->type == TOKEN_SH || policy->type == TOKEN_WSH || policy->type == TOKEN_TR;
}

static bool is_policy_name_acceptable(const char *name, size_t name_len) {
    // between 1 and MAX_POLICY_MAP_NAME_LENGTH characters
    if (name_len == 0 || name_len > MAX_POLICY_MAP_NAME_LENGTH) return false;

    // first and last characters must not be whitespace
    if (name[0] == ' ' || name[name_len - 1] == ' ') return false;

    // only allow ascii characters in the range from 0x20 to 0x7E (inclusive)
    for (unsigned int i = 0; i < name_len; i++)
        if (name[i] < 0x20 || name[i] > 0x7E) return false;

    return true;
}