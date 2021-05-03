/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  Y
 * ou may obtain a copy of the License at
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

#include "boilerplate/io.h"
#include "boilerplate/sw.h"
#include "../common/base58.h"
#include "../common/buffer.h"
#include "../common/merkle.h"
#include "../common/segwit_addr.h"
#include "../constants.h"
#include "../types.h"
#include "../crypto.h"
#include "../ui/display.h"
#include "../ui/menu.h"

#include "get_wallet_address.h"
#include "wallet.h"
#include "client_commands.h"

extern global_context_t G_context;

static void request_keys_order(dispatcher_context_t *dc);
static void receive_keys_order(dispatcher_context_t *dc);

static void request_next_cosigner(dispatcher_context_t *dc);
static void process_next_cosigner_info(dispatcher_context_t *dc);
static void generate_address(dispatcher_context_t *dc);
static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted);

void handler_get_wallet_address(
    uint8_t p1,
    uint8_t p2,
    uint8_t lc,
    dispatcher_context_t *dc
) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;
    if (p1 != 0 && p1 != 1) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    if (p2 != 0) {
        dc->send_sw(SW_WRONG_P1P2);
        return;
    }

    state->display_address = p1;

    // Device must be unlocked
    if (os_global_pin_is_validated() != BOLOS_UX_OK) {
        dc->send_sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        return;
    }

    uint8_t wallet_id[32];
    if (!buffer_read_bytes(&dc->read_buffer, wallet_id, 32)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t sig_len;
    uint8_t sig[MAX_DER_SIG_LEN];
    if (!buffer_read_u8(&dc->read_buffer, &sig_len) ||
        !buffer_read_bytes(&dc->read_buffer, sig, sig_len)
    ) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    // Verify signature
    if (!crypto_verify_sha256_hash(wallet_id, sig, sig_len)) {
        dc->send_sw(SW_SIGNATURE_FAIL);
        return;
    }

    if (read_wallet_header(&dc->read_buffer, &state->wallet_header) < 0) {
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
    if (!buffer_read_bytes(&dc->read_buffer, (uint8_t *)policy_map, policy_map_len)) {
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


    if (!buffer_read_u32(&dc->read_buffer, &state->address_index, BE)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }


    // Compute the wallet id (sha256 of the serialization)
    uint8_t computed_wallet_id[32];
    get_policy_wallet_id(&state->wallet_header,
                         policy_map_len,
                         policy_map,
                         state->wallet_header.multisig_policy.n_keys,
                         state->wallet_header.keys_info_merkle_root,
                         computed_wallet_id);

    if (memcmp(wallet_id, computed_wallet_id, sizeof(wallet_id)) != 0) {
        dc->send_sw(SW_INCORRECT_DATA); // TODO: more specific error code
        return;
    }

    /* STAGE 0 STARTS HERE */

    // Init command state
    state->shared.stage0.next_pubkey_index = 0;

    cx_sha256_init(&state->script_hash_context);

    uint8_t threshold = state->wallet_header.multisig_policy.threshold;
    crypto_hash_update_u8(&state->script_hash_context.header, 0x50 + threshold); // OP_m

    if (state->wallet_header.multisig_policy.sorted) {
        dc->next(request_keys_order);
    } else {
        // Keep the canonical order for multi()
        for (uint8_t i = 0; i < state->wallet_header.multisig_policy.n_keys; i++) {
            state->shared.stage0.ordered_pubkeys[i] = i;
        }
        dc->next(request_next_cosigner);
    }
}

// TODO: this processor and the next could be outsourced to a flow
static void request_keys_order(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t request[1 + 20 + 4 + 1 + 4*10 + 1 + 15]; // max size
    request[0] = CCMD_GET_PUBKEYS_IN_DERIVATION_ORDER;
    memcpy(request + 1, state->wallet_header.keys_info_merkle_root, 20);

    int pos = 1 + 20;

    write_u32_be(request, pos, state->wallet_header.multisig_policy.n_keys);
    pos += 4;

    request[pos++] = 2; // 2 derivation steps
    write_u32_be(request, pos, 0);
    pos += 4;
    write_u32_be(request, pos, state->address_index);
    pos += 4;

    request[pos++] = state->wallet_header.multisig_policy.n_keys;

    for (uint8_t i = 0; i < state->wallet_header.multisig_policy.n_keys; i++) {
        request[pos++] = i;
    }

    dc->send_response(request, pos, SW_INTERRUPTED_EXECUTION);
    dc->next(receive_keys_order);
}

static void receive_keys_order(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t n_key_indexes;
    if (!buffer_read_u8(&dc->read_buffer, &n_key_indexes) || !buffer_can_read(&dc->read_buffer, n_key_indexes)) {
        dc->send_sw(SW_WRONG_DATA_LENGTH);
        return;
    }

    if (n_key_indexes == 0 || n_key_indexes > 15) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    uint8_t seen_pubkeys[15];
    memset(seen_pubkeys, 0, sizeof(seen_pubkeys));

    // read the result, and make sure it is a permutation of [0, 1, ..., n_key_indexes - 1]
    for (int i = 0; i < n_key_indexes; i++) {
        uint8_t k;
        buffer_read_u8(&dc->read_buffer, &k);

        if (k >= n_key_indexes || seen_pubkeys[k] > 0) {
            dc->send_sw(SW_INCORRECT_DATA);
            return;
        }
        seen_pubkeys[k] = 1;

        state->shared.stage0.ordered_pubkeys[i] = k;
    }

    dc->next(request_next_cosigner);
}


/**
 * Interrupts the command, asking the host for the next pubkey.
 */
static void request_next_cosigner(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // we request a key, in the order committed in state->ordered_pubkeys

    call_get_merkle_leaf_element(dc,
                                 &state->subcontext.get_merkle_leaf_element,
                                 process_next_cosigner_info,
                                 state->wallet_header.keys_info_merkle_root,
                                 state->wallet_header.multisig_policy.n_keys,
                                 state->shared.stage0.ordered_pubkeys[state->shared.stage0.next_pubkey_index],
                                 state->shared.stage0.next_pubkey_info,
                                 sizeof(state->shared.stage0.next_pubkey_info));
}


/**
 * Receives the next pubkey, accumulates it in the hash context, derives the appropriate child key.
 */
static void process_next_cosigner_info(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    // Make a sub-buffer for the pubkey info
    buffer_t key_info_buffer = {
        .ptr = (uint8_t *)&state->shared.stage0.next_pubkey_info,
        .offset = 0,
        .size = state->subcontext.get_merkle_leaf_element.element_len
    };

    policy_map_key_info_t key_info;
    if (parse_policy_map_key_info(&key_info_buffer, &key_info) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }

    // decode pubkey
    serialized_extended_pubkey_check_t decoded_pubkey_check;
    if (base58_decode(key_info.ext_pubkey, strlen(key_info.ext_pubkey), (uint8_t *)&decoded_pubkey_check, sizeof(decoded_pubkey_check)) == -1) {
        dc->send_sw(SW_INCORRECT_DATA);
        return;
    }
    // TODO: validate checksum

    serialized_extended_pubkey_t *ext_pubkey = &decoded_pubkey_check.serialize_extended_pubkey;

    // we derive the /0/i child of this pubkey
    // we reuse the same memory of ext_pubkey to save RAM
    bip32_CKDpub(ext_pubkey, 0, ext_pubkey);
    bip32_CKDpub(ext_pubkey, state->address_index, ext_pubkey);

    // check lexicographic sorting if appropriate
    if (state->wallet_header.multisig_policy.sorted && state->shared.stage0.next_pubkey_index > 0) {
        if (memcmp(state->shared.stage0.prev_compressed_pubkey, ext_pubkey->compressed_pubkey, 33) >= 0) {
            dc->send_sw(SW_INCORRECT_DATA);
            return;
        }
    }

    memcpy(state->shared.stage0.prev_compressed_pubkey, ext_pubkey->compressed_pubkey, 33);

    // update script hash with PUSH opcode for this pubkey
    crypto_hash_update_u8(&state->script_hash_context.header, 0x21); // PUSH 33 bytes
    crypto_hash_update(&state->script_hash_context.header, ext_pubkey->compressed_pubkey, 33);

    // TODO: add push opcode to script hash (0x22<pubkey starting with 02 or 03>)
    ++state->shared.stage0.next_pubkey_index;
    if (state->shared.stage0.next_pubkey_index < state->wallet_header.multisig_policy.n_keys) {
        dc->next(request_next_cosigner);
    } else {
        dc->next(generate_address);
    }
}

/* STAGE 0 ENDS HERE */

/* STAGE 1 STARTS HERE */

static void generate_address(dispatcher_context_t *dc) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    LOG_PROCESSOR(dc, __FILE__, __LINE__, __func__);

    uint8_t n_keys = state->wallet_header.multisig_policy.n_keys;
    crypto_hash_update_u8(&state->script_hash_context.header, 0x50 + n_keys); // OP_n
    crypto_hash_update_u8(&state->script_hash_context.header, 0xae);          // OP_CHECKMULTISIG

    uint8_t script_sha256[32];
    crypto_hash_digest(&state->script_hash_context.header, script_sha256, 32);

    uint8_t script_rip[20];
    crypto_ripemd160(script_sha256, 32, script_rip);


    uint8_t redeem_script[34];
    uint8_t redeem_script_rip[20];

    int address_len;

    // TODO: extract address generation function from the script_sha256

    // Compute address
    int address_type = state->wallet_header.multisig_policy.address_type;
    switch (address_type) {
        case ADDRESS_TYPE_LEGACY:
            address_len = base58_encode_address(script_rip, G_context.p2sh_version, state->shared.stage1.address, sizeof(state->shared.stage1.address));
            if (address_len == -1) {
                dc->send_sw(SW_BAD_STATE); // should never happen
                return;
            } else {
                state->shared.stage1.address_len = (unsigned int)address_len;
            }

            break;
        case ADDRESS_TYPE_WIT:    // wrapped segwit
        case ADDRESS_TYPE_SH_WIT: // native segwit
            redeem_script[0] = 0x00; // OP_0
            redeem_script[1] = 0x20; // PUSH 32 bytes
            memcpy(&redeem_script[2], script_sha256, 32);

            crypto_hash160(redeem_script, 2 + 32, redeem_script_rip);
            if (address_type == ADDRESS_TYPE_SH_WIT) {
                int address_len = base58_encode_address(redeem_script_rip,
                                                        G_context.p2sh_version,
                                                        state->shared.stage1.address,
                                                        sizeof(state->shared.stage1.address));
                if (address_len == -1) {
                    dc->send_sw(SW_BAD_STATE); // should never happen
                    return;
                } else {
                    state->shared.stage1.address_len = (unsigned int)address_len;
                }
            } else { // address_type == ADDRESS_TYPE_WIT
                int ret = segwit_addr_encode(
                    state->shared.stage1.address,
                    G_context.native_segwit_prefix,
                    0, redeem_script + 2, 32
                );

                if (ret != 1) {
                    dc->send_sw(SW_BAD_STATE); // should never happen
                    return;
                }

                state->shared.stage1.address_len = strlen(state->shared.stage1.address);
            }
            break;
        default:
            dc->send_sw(SW_BAD_STATE);
            return; // this can never happen
    }
    state->shared.stage1.address[state->shared.stage1.address_len] = '\0';

    if (state->display_address == 0) {
        ui_action_validate_address(dc, true);
    } else {
        ui_display_wallet_address(dc, state->wallet_header.name, state->shared.stage1.address, ui_action_validate_address);
    }
}


static void ui_action_validate_address(dispatcher_context_t *dc, bool accepted) {
    get_wallet_address_state_t *state = (get_wallet_address_state_t *)&G_command_state;

    if (accepted) {
        dc->send_response(state->shared.stage1.address, state->shared.stage1.address_len, SW_OK);
    } else {
        dc->send_sw(SW_DENY);
    }

    dc->run();
}

/* STAGE 1 ENDS HERE */
