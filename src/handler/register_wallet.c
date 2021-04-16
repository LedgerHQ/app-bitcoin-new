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

#include "os.h"
#include "cx.h"

#include "../boilerplate/dispatcher.h"
#include "../boilerplate/sw.h"
#include "../common/write.h"
#include "../common/merkle.h"

#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "client_commands.h"

#include "register_wallet.h"
#include "wallet.h"

static void ui_action_validate_header(dispatcher_context_t *dc, bool accept);
static void request_next_cosigner(dispatcher_context_t *dc);
static void read_next_cosigner(dispatcher_context_t *dc);
static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept);


/**
 * Validates the input, initializes the hash context and starts accumulating the wallet header in it.
 */
void handler_register_wallet(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dc
) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (p1 != 0 || p2 != 0) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        dc->send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    int res;
    if ((res = read_wallet_header(&dc->read_buffer, &state->wallet_header)) < 0) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint16_t policy_map_len;
    if (!buffer_read_u16(&dc->read_buffer, &policy_map_len, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (policy_map_len > MAX_POLICY_MAP_LEN) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    char policy_map[MAX_POLICY_MAP_LEN];
    if (!buffer_read_bytes(&dc->read_buffer, policy_map, policy_map_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    buffer_t policy_map_buffer = {
        .ptr = (uint8_t *)&policy_map,
        .offset = 0,
        .size = policy_map_len
    };
    if (buffer_read_multisig_policy_map(&policy_map_buffer, &state->wallet_header.multisig_policy) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint16_t n_policy_keys;
    if (!buffer_read_u16(&dc->read_buffer, &n_policy_keys, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (n_policy_keys != state->wallet_header.multisig_policy.n_keys) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_read_bytes(&dc->read_buffer, state->wallet_header.keys_info_merkle_root, 20)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Compute the wallet id (sha256 of the serialization)
    get_policy_wallet_id(&state->wallet_header,
                         policy_map_len,
                         policy_map,
                         state->wallet_header.multisig_policy.n_keys,
                         state->wallet_header.keys_info_merkle_root,
                         state->wallet_id);

    state->next_pubkey_index = 0;

    PRINTF("SHOWING CONFIRMATION HEADER\n");

    dc->pause();
    // TODO: this does not show address type and if it's sorted. Is it a problem?
    //       a possible attack would be to show the user a different wallet rather than the correct one.
    //       Funds wouldn't be lost, but the user might think they are and fall victim of ransom nonetheless.
    ui_display_multisig_header(dc,
                               (char *)state->wallet_header.name,
                               state->wallet_header.multisig_policy.threshold,
                               state->wallet_header.multisig_policy.n_keys,
                               ui_action_validate_header);
}

/**
 * Abort if the user rejected the wallet header, otherwise start processing the pubkeys.
 */
static void ui_action_validate_header(dispatcher_context_t *dc, bool accept) {
    if (!accept) {
        dc->send_sw(SW_DENY);
    } else {
        dc->next(request_next_cosigner);
    }
    dc->run();
}

/**
 * Interrupts the command, asking the host for the next pubkey (in signing order).
 */
static void request_next_cosigner(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    uint8_t req[] = { CCMD_GET_PUBKEY_INFO, state->next_pubkey_index};

    dc->send_response(req, 2, SW_INTERRUPTED_EXECUTION);
    dc->next(read_next_cosigner);
}

/**
 * Receives and parses the next pubkey info and Merkle proof.
 * Checks the proof's validity, then asks the user to validate the pubkey info.
 */
static void read_next_cosigner(dispatcher_context_t *dc) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    uint8_t key_info_len;

    if (!buffer_read_u8(&dc->read_buffer, &key_info_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }
    if (key_info_len > MAX_MULTISIG_SIGNER_INFO_LEN) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    if (!buffer_can_read(&dc->read_buffer, key_info_len)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t key_info_hash[20];
    crypto_ripemd160(&dc->read_buffer.ptr[dc->read_buffer.offset], key_info_len, key_info_hash);

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = {
        .ptr = &dc->read_buffer.ptr[dc->read_buffer.offset],
        .offset = 0,
        .size = key_info_len
    };

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    buffer_seek_cur(&dc->read_buffer, key_info_len); // skip, data already parsed 

    // read Merkle proof and validate it.
    size_t proof_tree_size, proof_leaf_index;
    if (!buffer_read_u32(&dc->read_buffer, &proof_tree_size, BE) || !buffer_read_u32(&dc->read_buffer, &proof_leaf_index, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (!buffer_read_and_verify_merkle_proof(&dc->read_buffer,
                                             state->wallet_header.keys_info_merkle_root,
                                             proof_tree_size,
                                             proof_leaf_index,
                                             key_info_hash)) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }


    // TODO: it would be sensible to validate the pubkey (at least syntactically + validate checksum)
    //       Currently we are showing to the user whichever string is passed by the host.

    dc->pause();
    ui_display_multisig_cosigner_pubkey(dc,
                                        key_info.ext_pubkey,
                                        state->next_pubkey_index, // 1-indexed for the UI
                                        state->wallet_header.multisig_policy.n_keys,
                                        ui_action_validate_cosigner);
}

/**
 * Aborts if the user rejected the pubkey; if more xpubs are to be read, goes back to request_next_cosigner.
 * Otherwise, finalizes the hash, and returns the sha256 digest and the signature as the final response.
 */
static void ui_action_validate_cosigner(dispatcher_context_t *dc, bool accept) {
    register_wallet_state_t *state = (register_wallet_state_t *)&G_command_state;

    if (!accept) {
        dc->send_sw(SW_DENY);
        dc->run();
        return;
    }
 
    ++state->next_pubkey_index;
    if (state->next_pubkey_index < state->wallet_header.multisig_policy.n_keys) {
        dc->next(request_next_cosigner);
    } else {

        // TODO: validate wallet.
        // - is one of the xpubs ours? (exactly one? How to check?)

        struct {
            uint8_t wallet_id[32];
            uint8_t signature_len;
            uint8_t signature[MAX_DER_SIG_LEN]; // the actual response might be shorter
        } response;

        memcpy(response.wallet_id, state->wallet_id, sizeof(state->wallet_id));

        // TODO: HMAC should be good enough in this case, and much faster; also, shorter than sigs

        // sign wallet id and produce response
        int signature_len = crypto_sign_sha256_hash(state->wallet_id, response.signature);
        response.signature_len = (uint8_t)signature_len;

        dc->send_response(&response, 32 + 1 + signature_len, SW_OK);
    }

    dc->run();
}
